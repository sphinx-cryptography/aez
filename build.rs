fn main() {
    cc::Build::new()
        .file("aez5-impls/aesni/encrypt.c")
        .flag_if_supported("-msse2")
        .flag_if_supported("-march=native")
        .flag_if_supported("-maes")
        .compile("aez");
}
