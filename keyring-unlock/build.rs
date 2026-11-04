use std::{env, fs, path::PathBuf};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let directory = root.join("../i18n");
    println!("cargo:rerun-if-changed={}", directory.display());
    let mut codes: Vec<_> = fs::read_dir(directory)
        .expect("read localization catalogs")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|value| value == "json"))
        .map(|path| path.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    codes.sort();
    let mut source = String::from("const CATALOGS: &[(&str, &str)] = &[\n");
    for code in codes {
        source.push_str(&format!(
            "({code:?}, include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../i18n/{code}.json\"))),\n"
        ));
    }
    source.push_str("];\n");
    fs::write(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("catalogs.rs"), source).unwrap();
}
