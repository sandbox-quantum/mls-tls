use mls_rs::{Group, client_builder::MlsConfig, group::Node};

pub fn print_tree_detailed(group: &Group<impl MlsConfig>) {
    print_tree_inner(group, true);
}

pub fn print_tree(group: &Group<impl MlsConfig>) {
    print_tree_inner(group, false);
}

fn print_tree_inner(group: &Group<impl MlsConfig>, detailed: bool) {
    println!(
        "Group id={} epoch={} cipher_suite={:?} my_index={}",
        hex::encode(group.group_id()),
        group.current_epoch(),
        group.cipher_suite(),
        group.current_member_index()
    );

    let tree = group.export_tree();
    let nodes = tree.nodes();
    let n = nodes.len();
    if n == 0 {
        return;
    }

    let root = tree_root(n);
    print_node(nodes, root, n, "", true, detailed);
}

fn tree_level(x: usize) -> u32 {
    (x as u32).trailing_ones()
}

fn tree_root(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (1usize << (usize::BITS - n.leading_zeros() - 1)) - 1
}

fn tree_left(x: usize) -> usize {
    let k = tree_level(x);
    x ^ (1 << (k - 1))
}

fn tree_right(x: usize, n: usize) -> usize {
    let k = tree_level(x);
    let mut r = x ^ (3 << (k - 1));
    while r >= n {
        let rk = tree_level(r);
        r ^= 1 << (rk - 1);
    }
    r
}

fn format_node(node: &Option<Node>, index: usize, detailed: bool) -> String {
    match node {
        Some(Node::Leaf(leaf)) => {
            let cred = &leaf.signing_identity.credential;
            let cred_str = match cred {
                mls_rs::identity::Credential::Basic(b) => {
                    format!("Basic(\"{}\")", String::from_utf8_lossy(&b.identifier))
                }
                mls_rs::identity::Credential::X509(_) => "X509".into(),
                mls_rs::identity::Credential::Custom(c) => {
                    format!("Custom({})", c.credential_type.raw_value())
                }
                _ => "Unknown".into(),
            };
            let leaf_index = index / 2;
            let pk = &leaf.signing_identity.signature_key;
            let mut s = format!(
                "Leaf[{leaf_index}] {cred_str} pk={:02x?}..",
                &pk.as_ref()[..4.min(pk.as_ref().len())]
            );
            if detailed {
                s.push_str(&format!(
                    "\n         sig_key={}",
                    hex::encode(pk.as_ref())
                ));
                let hpke = &leaf.public_key;
                s.push_str(&format!(
                    "\n         hpke_pk={}",
                    hex::encode(hpke.as_ref())
                ));
            }
            s
        }
        Some(Node::Parent(parent)) => {
            let pk = &parent.public_key;
            let mut s = format!(
                "Parent pk={:02x?}..",
                &pk.as_ref()[..4.min(pk.as_ref().len())]
            );
            if detailed {
                s.push_str(&format!(
                    "\n         hpke_pk={}",
                    hex::encode(pk.as_ref())
                ));
            }
            s
        }
        None => "(blank)".into(),
    }
}

fn print_node(nodes: &[Option<Node>], index: usize, n: usize, prefix: &str, is_last: bool, detailed: bool) {
    let connector = if is_last { "`- " } else { "|- " };
    println!("{prefix}{connector}{}", format_node(&nodes[index], index, detailed));

    if tree_level(index) == 0 {
        return;
    }

    let child_prefix = format!("{prefix}{}", if is_last { "   " } else { "|  " });
    let left = tree_left(index);
    let right = tree_right(index, n);

    print_node(nodes, left, n, &child_prefix, false, detailed);
    print_node(nodes, right, n, &child_prefix, true, detailed);
}
