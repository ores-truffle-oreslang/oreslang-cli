use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stamp {
    exists: bool,
    len: u64,
    modified_nanos: u128,
}

impl Stamp {
    fn read(path: &Path) -> Self {
        let Ok(metadata) = fs::metadata(path) else {
            return Self {
                exists: false,
                len: 0,
                modified_nanos: 0,
            };
        };
        let modified_nanos = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        Self {
            exists: true,
            len: metadata.len(),
            modified_nanos,
        }
    }
}

enum Command {
    Add(PathBuf),
    Remove(PathBuf),
    Shutdown,
}

/// Portable polling watcher used by the LSP session.
///
/// Native platform watchers can replace this behind the same API later.
/// Polling avoids extra runtime dependencies and has deterministic behavior
/// across macOS, Linux, and Windows.
pub struct PollingWatcher {
    commands: Sender<Command>,
    worker: Option<JoinHandle<()>>,
}

impl PollingWatcher {
    pub fn start(interval: Duration) -> (Self, Receiver<PathBuf>) {
        let (commands, command_rx) = mpsc::channel();
        let (changes, change_rx) = mpsc::channel();

        let worker = thread::Builder::new()
            .name("oreslang-file-watcher".to_owned())
            .spawn(move || {
                let mut watched: HashMap<PathBuf, Stamp> = HashMap::new();

                loop {
                    match command_rx.recv_timeout(interval) {
                        Ok(Command::Add(path)) => {
                            let stamp = Stamp::read(&path);
                            watched.insert(path, stamp);
                        }
                        Ok(Command::Remove(path)) => {
                            watched.remove(&path);
                        }
                        Ok(Command::Shutdown) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            for (path, previous) in &mut watched {
                                let current = Stamp::read(path);
                                if current != *previous {
                                    *previous = current;
                                    let _ = changes.send(path.clone());
                                }
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            })
            .expect("spawn Oreslang file watcher");

        (
            Self {
                commands,
                worker: Some(worker),
            },
            change_rx,
        )
    }

    pub fn add(&self, path: PathBuf) {
        let _ = self.commands.send(Command::Add(path));
    }

    pub fn remove(&self, path: PathBuf) {
        let _ = self.commands.send(Command::Remove(path));
    }
}

impl Drop for PollingWatcher {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
