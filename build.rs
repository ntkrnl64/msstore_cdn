fn main() {
    #[cfg(target_os = "windows")]
    embed_resource::compile("msstore_cdn.rc", embed_resource::NONE);
}
