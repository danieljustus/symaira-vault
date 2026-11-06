//! Frozen drift guard for the built-in API templates.
//!
//! The 17 templates are compiled into `symvault-mcp` from `assets/apitemplates/`.
//! They were byte-identical to the Go tree's embedded copy
//! (`internal/mcp/apitemplates/builtin/`) when that copy was last compared; the
//! sha256 of each file is frozen below, so an edit of an asset is a deliberate
//! change that has to update this list (and no Go tree is needed).

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

/// `(file name, sha256 of the LF-normalized bytes)`.
const FROZEN: [(&str, &str); 17] = [
    (
        "anthropic.yaml",
        "d4c1fdf900c032ef04e53ed3147800b3643bd048c0d0c3cbe285cababe9ca387",
    ),
    (
        "cloudflare.yaml",
        "9bc1be5e765e930fb2cd0f1dc393fd8e774a0e4bfeb16def842903cf31d30d16",
    ),
    (
        "gemini.yaml",
        "5c5f84cd43bf3d49a0fcac2df75e93a05621e9c7874193b5e77a8742fdc51f22",
    ),
    (
        "github.yaml",
        "629d873101d86050cfb18d7276d07b9ded77efed020b3d36fe1d6cc001ab60f3",
    ),
    (
        "gitlab.yaml",
        "958d1b65557d064b423197a80648c889eeb37fe792601a7948e1d60c42acfa33",
    ),
    (
        "linear.yaml",
        "eddb150d4eaa68ae2b48ef30bf81a28375cb11bc6f326fbd9ce62784acdd7468",
    ),
    (
        "notion.yaml",
        "28b7d45d2e7cbf106f408bdd65e87da6f7157f8aa3087b906651f247914832c0",
    ),
    (
        "npm.yaml",
        "a759d9f840321a1ca6a680db207f106da4a12003813ff8cae7648f000f27c014",
    ),
    (
        "openai.yaml",
        "99583828518aa07d6b1f38ca277e8d7ab7579690450c3d7f2514531f3865e87a",
    ),
    (
        "openrouter.yaml",
        "365815a09ab0d1eef84eb2855f88e39ebe61b1514ad655164572a93b32264741",
    ),
    (
        "perplexity.yaml",
        "30235afc33a5dbb7f0662da44dba12a0967ed564379c45db47e8c1f92fcbb2c7",
    ),
    (
        "resend.yaml",
        "2fee91ff1a7b2402ba25476085465a5906c086a094399b7d340c0a468646eb35",
    ),
    (
        "sentry.yaml",
        "01b07699d19154eeb55f6cadbe3ccc6452d2e7e6375890d6d4947ba598ae2292",
    ),
    (
        "slack.yaml",
        "c3186c5409c4c3cc5151b4cf3af0334b9606056bfc7cf751060fc76f225dd595",
    ),
    (
        "stripe.yaml",
        "118960d01dfda432683c312c2baa0471416b04714b360a682fa99eca78451874",
    ),
    (
        "telegram.yaml",
        "86fda3d87c7a97574f0e627ee15903796a045dea44cc44d0f7b5fdc7bd629b4f",
    ),
    (
        "vercel.yaml",
        "42ebb1c5c98b918272a7b0faef7bd36e3273d9b78f86452dce861437de481e56",
    ),
];

#[test]
fn built_in_templates_match_the_frozen_sha256_list() {
    let assets = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/apitemplates");
    let mut names: Vec<String> = fs::read_dir(&assets)
        .expect("crate-local template assets exist")
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    let frozen: Vec<&str> = FROZEN.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names, frozen,
        "template file sets diverged from the frozen list"
    );
    for (name, expected) in FROZEN {
        let text = String::from_utf8(fs::read(assets.join(name)).unwrap()).unwrap();
        let normalized = text.replace("\r\n", "\n");
        assert_eq!(
            hex::encode(Sha256::digest(normalized.as_bytes())),
            expected,
            "{name} drifted from the frozen Go-era copy"
        );
    }
}
