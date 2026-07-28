#[cfg(windows)]
fn main() {
    let mut res = winres::WindowsResource::new();
    // Icone do RagnaLinK. O rpatchur.ico original continua na pasta, como
    // referencia - basta trocar o nome aqui pra voltar atras.
    res.set_icon("resources/ragnalink.ico");
    res.compile().unwrap();
}

#[cfg(unix)]
fn main() {}
