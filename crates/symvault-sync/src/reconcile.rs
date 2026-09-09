use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReconcileInput {
    pub base: BTreeMap<String, Vec<u8>>,
    pub local: BTreeMap<String, Vec<u8>>,
    pub remote: BTreeMap<String, Vec<u8>>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Conflict {
    pub path: String,
    pub local: Vec<u8>,
    pub remote: Vec<u8>,
    pub conflict_path: String,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReconcileOutput {
    pub files: BTreeMap<String, Vec<u8>>,
    pub conflicts: Vec<Conflict>,
    pub changed: Vec<String>,
}

/// Three-way reconciliation. Unchanged sides inherit the changed side; when
/// both sides differ, local bytes remain authoritative and remote bytes are
/// retained under a stable `.conflict-remote` copy. BTreeMap ordering makes the
/// result independent of filesystem or map iteration order.
pub fn reconcile(input: &ReconcileInput) -> ReconcileOutput {
    let mut keys = std::collections::BTreeSet::new();
    keys.extend(input.base.keys().cloned());
    keys.extend(input.local.keys().cloned());
    keys.extend(input.remote.keys().cloned());
    let mut out = ReconcileOutput::default();
    for path in keys {
        let base = input.base.get(&path);
        let local = input.local.get(&path);
        let remote = input.remote.get(&path);
        let chosen = match (local, remote, base) {
            (Some(l), Some(r), _) if l == r => Some(l.clone()),
            (l, r, b) if l == b => r.cloned(),
            (l, r, b) if r == b => l.cloned(),
            (Some(l), Some(r), _) => {
                let conflict_path = format!("{path}.conflict-remote");
                out.conflicts.push(Conflict {
                    path: path.clone(),
                    local: l.clone(),
                    remote: r.clone(),
                    conflict_path: conflict_path.clone(),
                });
                out.files.insert(conflict_path.clone(), r.clone());
                out.changed.push(conflict_path);
                Some(l.clone())
            }
            (Some(l), None, Some(b)) if l == b => None,
            (None, Some(r), Some(b)) if r == b => None,
            (Some(l), None, _) => Some(l.clone()),
            (None, Some(r), _) => Some(r.clone()),
            (None, None, _) => None,
        };
        if let Some(bytes) = chosen {
            if input.base.get(&path) != Some(&bytes) {
                out.changed.push(path.clone());
            }
            out.files.insert(path, bytes);
        }
    }
    out.changed.sort();
    out.conflicts.sort_by(|a, b| a.path.cmp(&b.path));
    out
}
