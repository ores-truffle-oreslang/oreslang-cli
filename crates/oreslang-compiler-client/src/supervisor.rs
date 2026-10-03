use crate::{absolute_path, CheckResult, CompilerClient, CompilerClientError, CompilerCommand};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::UNIX_EPOCH;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileFingerprint {
    len: u64,
    modified_nanos: u128,
}

impl FileFingerprint {
    fn read(path: &Path) -> Option<Self> {
        let metadata = fs::metadata(path).ok()?;
        let modified_nanos = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        Some(Self {
            len: metadata.len(),
            modified_nanos,
        })
    }
}

enum Request {
    Check {
        path: PathBuf,
        response: Sender<Result<CheckResult, CompilerClientError>>,
    },
    Invalidate(PathBuf),
    Shutdown,
}

/// Long-lived Rust-side compiler session.
///
/// The supervisor serializes compiler access, caches results for unchanged
/// files, and survives individual backend failures or panics. The current
/// Java compiler adapter is still one-shot; when the compiler exposes a
/// persistent RPC mode this type is the lifecycle boundary that will own it.
pub struct CompilerSupervisor {
    requests: Sender<Request>,
    worker: Option<JoinHandle<()>>,
}

impl CompilerSupervisor {
    pub fn start(command: CompilerCommand) -> Self {
        let (requests, receiver) = mpsc::channel::<Request>();
        let worker = thread::Builder::new()
            .name("oreslang-compiler-supervisor".to_owned())
            .spawn(move || {
                let client = CompilerClient::new(command);
                let mut cache: HashMap<PathBuf, (FileFingerprint, CheckResult)> = HashMap::new();

                while let Ok(request) = receiver.recv() {
                    match request {
                        Request::Check { path, response } => {
                            let absolute = absolute_path(&path).unwrap_or(path);
                            let fingerprint = FileFingerprint::read(&absolute);

                            if let Some(fingerprint) = fingerprint {
                                if let Some((cached_fingerprint, cached_result)) =
                                    cache.get(&absolute)
                                {
                                    if *cached_fingerprint == fingerprint {
                                        let _ = response.send(Ok(cached_result.clone()));
                                        continue;
                                    }
                                }
                            }

                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    client.check_file(&absolute)
                                }))
                                .unwrap_or(Err(CompilerClientError::WorkerPanicked));

                            if let (Some(fingerprint), Ok(check_result)) = (fingerprint, &result) {
                                cache.insert(absolute.clone(), (fingerprint, check_result.clone()));
                            }

                            let _ = response.send(result);
                        }
                        Request::Invalidate(path) => {
                            let absolute = absolute_path(&path).unwrap_or(path);
                            cache.remove(&absolute);
                        }
                        Request::Shutdown => break,
                    }
                }
            })
            .expect("spawn Oreslang compiler supervisor");

        Self {
            requests,
            worker: Some(worker),
        }
    }

    pub fn check_file_async(
        &self,
        path: impl Into<PathBuf>,
    ) -> Result<Receiver<Result<CheckResult, CompilerClientError>>, CompilerClientError> {
        let (response, receiver) = mpsc::channel();
        self.requests
            .send(Request::Check {
                path: path.into(),
                response,
            })
            .map_err(|_| CompilerClientError::SupervisorClosed)?;
        Ok(receiver)
    }

    pub fn invalidate(&self, path: impl Into<PathBuf>) -> Result<(), CompilerClientError> {
        self.requests
            .send(Request::Invalidate(path.into()))
            .map_err(|_| CompilerClientError::SupervisorClosed)
    }
}

impl Drop for CompilerSupervisor {
    fn drop(&mut self) {
        let _ = self.requests.send(Request::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_changes_when_file_changes() {
        let base = std::env::temp_dir().join(format!(
            "oreslang-supervisor-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_file(&base);
        fs::write(&base, "a").expect("write");
        let first = FileFingerprint::read(&base).expect("fingerprint");
        fs::write(&base, "longer").expect("rewrite");
        let second = FileFingerprint::read(&base).expect("fingerprint");
        let _ = fs::remove_file(&base);
        assert_ne!(first, second);
    }
}
