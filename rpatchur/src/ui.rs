use std::fs;
use std::path::PathBuf;

use crate::patcher::{get_patcher_name, PatcherCommand, PatcherConfiguration};
use crate::process::start_executable;
use serde::Deserialize;
use serde_json::Value;
use tinyfiledialogs as tfd;
use web_view::{Content, Handle, WebView};

/// 'Opaque" struct that can be used to update the UI.
pub struct UiController {
    web_view_handle: Handle<WebViewUserData>,
}
impl UiController {
    pub fn new(web_view: &WebView<'_, WebViewUserData>) -> UiController {
        UiController {
            web_view_handle: web_view.handle(),
        }
    }

    /// Allows another thread to indicate the current status of the patching process.
    ///
    /// This updates the UI with useful information.
    pub fn dispatch_patching_status(&self, status: PatchingStatus) {
        if let Err(e) = self.web_view_handle.dispatch(move |webview| {
            let result = match status {
                PatchingStatus::Ready => webview.eval("patchingStatusReady()"),
                PatchingStatus::Error(msg) => {
                    webview.eval(&format!("patchingStatusError(\"{}\")", msg))
                }
                PatchingStatus::DownloadInProgress(nb_downloaded, nb_total, bytes_per_sec) => {
                    webview.eval(&format!(
                        "patchingStatusDownloading({}, {}, {})",
                        nb_downloaded, nb_total, bytes_per_sec
                    ))
                }
                PatchingStatus::InstallationInProgress(nb_installed, nb_total) => webview.eval(
                    &format!("patchingStatusInstalling({}, {})", nb_installed, nb_total),
                ),
                PatchingStatus::ManualPatchApplied(name) => {
                    webview.eval(&format!("patchingStatusPatchApplied(\"{}\")", name))
                }
            };
            if let Err(e) = result {
                log::warn!("Failed to dispatch patching status: {}.", e);
            }
            Ok(())
        }) {
            log::warn!("Failed to dispatch patching status: {}.", e);
        }
    }

    pub fn set_patch_in_progress(&self, value: bool) {
        if let Err(e) = self.web_view_handle.dispatch(move |webview| {
            webview.user_data_mut().patching_in_progress = value;
            Ok(())
        }) {
            log::warn!("Failed to dispatch patching status: {}.", e);
        }
    }
}

/// Used to indicate the current status of the patching process.
pub enum PatchingStatus {
    Ready,
    Error(String),                         // Error message
    DownloadInProgress(usize, usize, u64), // Downloaded files, Total number, Bytes per second
    InstallationInProgress(usize, usize),  // Installed patches, Total number
    ManualPatchApplied(String),            // Patch file name
}

pub struct WebViewUserData {
    patcher_config: PatcherConfiguration,
    patching_thread_tx: flume::Sender<PatcherCommand>,
    patching_in_progress: bool,
}
impl WebViewUserData {
    pub fn new(
        patcher_config: PatcherConfiguration,
        patching_thread_tx: flume::Sender<PatcherCommand>,
    ) -> WebViewUserData {
        WebViewUserData {
            patcher_config,
            patching_thread_tx,
            patching_in_progress: false,
        }
    }
}
impl Drop for WebViewUserData {
    fn drop(&mut self) {
        // Ask the patching thread to stop whenever WebViewUserData is dropped
        let _res = self.patching_thread_tx.try_send(PatcherCommand::Quit);
    }
}

/// Creates a `WebView` object with the appropriate settings for our needs.
pub fn build_webview<'a>(
    title: &'a str,
    user_data: WebViewUserData,
) -> web_view::WVResult<WebView<'a, WebViewUserData>> {
    web_view::builder()
        .title(title)
        .content(Content::Url(user_data.patcher_config.web.index_url.clone()))
        .size(
            user_data.patcher_config.window.width,
            user_data.patcher_config.window.height,
        )
        .resizable(user_data.patcher_config.window.resizable)
        .frameless(user_data.patcher_config.window.frameless.unwrap_or(false))
        .user_data(user_data)
        .invoke_handler(|webview, arg| {
            match arg {
                "play" => handle_play(webview),
                "setup" => handle_setup(webview),
                "exit" => handle_exit(webview),
                "start_update" => handle_start_update(webview),
                "cancel_update" => handle_cancel_update(webview),
                "reset_cache" => handle_reset_cache(webview),
                "manual_patch" => handle_manual_patch(webview),
                "ajustar_janela" => handle_ajustar_janela(webview),
                "moldar_janela" => handle_moldar_janela(),
                "minimize" => handle_minimize(),
                "drag" => handle_drag(),
                request => handle_json_request(webview, request),
            }
            Ok(())
        })
        .build()
}

/// Opens the configured game client with the configured arguments.
///
/// This function can create elevated processes on Windows with UAC activated.
fn handle_play(webview: &mut WebView<WebViewUserData>) {
    let client_arguments = webview.user_data().patcher_config.play.arguments.clone();
    start_game_client(webview, &client_arguments);
}

/// Opens the configured 'Setup' software with the configured arguments.
///
/// This function can create elevated processes on Windows with UAC activated.
fn handle_setup(webview: &mut WebView<WebViewUserData>) {
    let setup_exe: &String = &webview.user_data().patcher_config.setup.path;
    let setup_arguments = &webview.user_data().patcher_config.setup.arguments;
    let exit_on_success = webview
        .user_data()
        .patcher_config
        .setup
        .exit_on_success
        .unwrap_or(false);
    match start_executable(setup_exe, setup_arguments) {
        Ok(success) => {
            if success {
                log::trace!("Setup software started");
                if exit_on_success {
                    webview.exit();
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to start setup software: {}", e);
        }
    }
}

/// Exits the patcher cleanly.
fn handle_exit(webview: &mut WebView<WebViewUserData>) {
    webview.exit();
}

/// Starts the patching task/thread.
fn handle_start_update(webview: &mut WebView<WebViewUserData>) {
    // Patching is already in progress, abort.
    if webview.user_data().patching_in_progress {
        let res = webview.eval("notificationInProgress()");
        if let Err(e) = res {
            log::warn!("Failed to dispatch notification: {}.", e);
        }
        return;
    }

    let send_res = webview
        .user_data_mut()
        .patching_thread_tx
        .send(PatcherCommand::StartUpdate);
    if send_res.is_ok() {
        log::trace!("Sent StartUpdate command to patching thread");
    }
}

/// Cancels the patching task/thread.
fn handle_cancel_update(webview: &mut WebView<WebViewUserData>) {
    if webview
        .user_data_mut()
        .patching_thread_tx
        .send(PatcherCommand::CancelUpdate)
        .is_ok()
    {
        log::trace!("Sent CancelUpdate command to patching thread");
    }
}

/// Resets the patcher cache (which is used to keep track of already applied
/// patches).
fn handle_reset_cache(_webview: &mut WebView<WebViewUserData>) {
    if let Ok(patcher_name) = get_patcher_name() {
        let cache_file_path = PathBuf::from(patcher_name).with_extension("dat");
        if let Err(e) = fs::remove_file(cache_file_path) {
            log::warn!("Failed to remove the cache file: {}", e);
        }
    }
}

/// Asks the user to provide a patch file to apply
fn handle_manual_patch(webview: &mut WebView<WebViewUserData>) {
    // Patching is already in progress, abort.
    if webview.user_data().patching_in_progress {
        let res = webview.eval("notificationInProgress()");
        if let Err(e) = res {
            log::warn!("Failed to dispatch notification: {}.", e);
        }
        return;
    }

    let opt_path = tfd::open_file_dialog(
        "Select a file",
        "",
        Some((&["*.thor"], "Patch Files (*.thor)")),
    );
    if let Some(path) = opt_path {
        log::info!("Requesting manual patch '{}'", path);
        if webview
            .user_data_mut()
            .patching_thread_tx
            .send(PatcherCommand::ApplyPatch(PathBuf::from(path)))
            .is_ok()
        {
            log::trace!("Sent ApplyPatch command to patching thread");
        }
    }
}

// ===========================================================================
//  Comandos de janela — usados quando o patcher roda sem a barra do Windows
// ===========================================================================
//
// Sem a barra, o sistema operacional deixa de oferecer fechar, minimizar e
// arrastar. Fechar ja existia ("exit"); os outros dois precisam falar com a API
// do Windows direto, porque o web-view 0.7.3 nao expoe nada disso.

/// Localiza a janela principal do patcher.
///
/// O web-view 0.7.3 NAO expoe o handle nativo, entao e preciso procura-lo. Entre as
/// opcoes, esta e a menos fragil: varrer as janelas de nivel superior da THREAD ATUAL.
/// O `invoke_handler` roda na thread da interface, que e a dona da janela.
///
/// A alternativa obvia seria `FindWindow` pelo titulo, mas o titulo vem do arquivo de
/// configuracao do servidor: bastaria alguem renomear a janela no yml para o minimizar
/// e o arrastar pararem de funcionar, sem nenhum erro visivel. Amarrar a funcionalidade
/// a um texto editavel e pedir para quebrar.
///
/// O filtro de visivel + sem dono e necessario porque o MSHTML cria janelas auxiliares
/// na mesma thread; agir sobre uma delas moveria ou minimizaria a coisa errada.
#[cfg(windows)]
fn janela_principal() -> Option<winapi::shared::windef::HWND> {
    use std::ptr;
    use winapi::shared::minwindef::{BOOL, FALSE, LPARAM, TRUE};
    use winapi::shared::windef::HWND;
    use winapi::um::processthreadsapi::GetCurrentThreadId;
    use winapi::um::winuser::{EnumThreadWindows, GetWindow, IsWindowVisible, GW_OWNER};

    unsafe extern "system" fn visitar(hwnd: HWND, lparam: LPARAM) -> BOOL {
        if IsWindowVisible(hwnd) == TRUE && GetWindow(hwnd, GW_OWNER).is_null() {
            let saida = lparam as *mut HWND;
            if (*saida).is_null() {
                *saida = hwnd;
                return FALSE; // achou: interrompe a varredura
            }
        }
        TRUE
    }

    let mut achada: HWND = ptr::null_mut();
    unsafe {
        EnumThreadWindows(
            GetCurrentThreadId(),
            Some(visitar),
            &mut achada as *mut HWND as LPARAM,
        );
    }
    if achada.is_null() {
        log::warn!("Could not find the patcher's main window");
        None
    } else {
        Some(achada)
    }
}

/// Encaixa a janela no tamanho do componente do navegador.
///
/// 🚨 POR QUE ISTO EXISTE: com `frameless`, o web-view continua calculando o tamanho
/// da janela como se houvesse moldura - ele soma a barra de titulo e as bordas ao
/// tamanho pedido. Sem moldura, essa sobra (cerca de 22px de largura e 29 de altura)
/// vira area de conteudo VAZIA, e o componente do navegador, criado com o tamanho
/// original, nao a cobre. O resultado e uma faixa em "L" branca na direita e embaixo,
/// desenhada pelo fundo da janela.
///
/// Nenhum CSS alcanca aquilo - confirmado pintando o corpo da pagina de vermelho:
/// o vermelho parou na borda e o "L" continuou branco.
///
/// A correcao e reduzir a JANELA ate o tamanho pedido na configuracao. Sem moldura,
/// area de conteudo e janela passam a ter a mesma medida, e o componente encaixa
/// exatamente. A pagina chama isto uma vez, ao abrir.
#[cfg(windows)]
fn handle_ajustar_janela(webview: &mut WebView<WebViewUserData>) {
    use std::ptr;
    use winapi::um::winuser::{SetWindowPos, SWP_FRAMECHANGED, SWP_NOMOVE, SWP_NOZORDER};
    let largura = webview.user_data().patcher_config.window.width;
    let altura = webview.user_data().patcher_config.window.height;
    if let Some(hwnd) = janela_principal() {
        unsafe {
            SetWindowPos(
                hwnd,
                ptr::null_mut(),
                0,
                0,
                largura,
                altura,
                SWP_NOMOVE | SWP_NOZORDER | SWP_FRAMECHANGED,
            );
        }
    }
}

/// Forma da janela, em retangulos. Gerado junto com o `fundo.png` pelo script
/// `fundo_limpo.py`, a partir do canal alfa da propria arte - por isso arte e recorte
/// nunca saem de sincronia.
///
/// Vai embutido no executavel com `include_str!`, e nao lido do disco, de proposito:
/// arquivo solto poderia sumir, ser editado ou vir truncado na maquina do jogador, e
/// o sintoma seria uma janela cortada errado, sem nenhuma mensagem de erro.
#[cfg(windows)]
const FORMA: &str = include_str!("../resources/forma.txt");

/// Recorta a janela no formato da arte.
///
/// POR QUE REGIAO E NAO TRANSPARENCIA POR PIXEL: a borda macia com brilho e sombra
/// exigiria `UpdateLayeredWindow`, que pinta a janela a partir de um bitmap fornecido
/// por nos. So que quem desenha aqui e o MSHTML, num controle FILHO - e controle filho
/// nao entra na superficie alfa da janela pai. Nao e questao de esforco: com este
/// motor de renderizacao nao da. Regiao e o caminho que sobra, e ela recorta com borda
/// dura. E por isso que a arte tem um contorno escuro desenhado exatamente em cima da
/// silhueta: e ele que faz o serrilhado ler como acabamento.
///
/// A regiao e montada em pixels de JANELA. Como o modo sem moldura nao tem area
/// nao-cliente, janela e area de conteudo coincidem, e as coordenadas daqui sao as
/// mesmas do CSS da pagina.
///
/// 🚨 CHAMAR SEMPRE DEPOIS DO `ajustar_janela`. Aquele redimensiona a janela; esta
/// aqui recorta o resultado. Na ordem trocada o recorte ficaria certo do mesmo jeito
/// (a regiao nao depende do tamanho), mas existiria um instante com a janela grande e
/// ja recortada, que pisca feio na abertura.
#[cfg(windows)]
fn handle_moldar_janela() {
    use winapi::shared::minwindef::TRUE;
    use winapi::um::wingdi::{CombineRgn, CreateRectRgn, DeleteObject, SetRectRgn, RGN_OR};
    use winapi::um::winuser::SetWindowRgn;

    let hwnd = match janela_principal() {
        Some(h) => h,
        None => return,
    };

    unsafe {
        let regiao = CreateRectRgn(0, 0, 0, 0); // comeca vazia e vai crescendo
        let peca = CreateRectRgn(0, 0, 0, 0); // reaproveitada a cada retangulo
        if regiao.is_null() || peca.is_null() {
            log::error!("Could not create the window region");
            if !regiao.is_null() {
                DeleteObject(regiao as _);
            }
            if !peca.is_null() {
                DeleteObject(peca as _);
            }
            return;
        }

        let mut total = 0usize;
        for (numero, linha) in FORMA.lines().enumerate() {
            let linha = linha.trim();
            if linha.is_empty() || linha.starts_with('#') {
                continue;
            }
            let mut campos = linha.split_whitespace().map(str::parse::<i32>);
            match (campos.next(), campos.next(), campos.next(), campos.next()) {
                (Some(Ok(esq)), Some(Ok(topo)), Some(Ok(dir)), Some(Ok(baixo))) => {
                    // Reusar uma unica peca evita criar e destruir um objeto GDI por
                    // retangulo. Sao poucas centenas, mas objeto GDI e recurso escasso
                    // e vazar um por engano custa caro num programa que fica aberto.
                    SetRectRgn(peca, esq, topo, dir, baixo);
                    CombineRgn(regiao, regiao, peca, RGN_OR);
                    total += 1;
                }
                _ => log::warn!("Malformed rectangle on line {} of forma.txt", numero + 1),
            }
        }
        DeleteObject(peca as _);

        if total == 0 {
            // Regiao vazia faz a janela DESAPARECER da tela, e sem barra de titulo o
            // jogador nao teria como fechar nem mover. Diante de um arquivo quebrado,
            // janela retangular e um defeito visual; janela invisivel e um travamento.
            log::error!("forma.txt has no usable rectangles; leaving the window unshaped");
            DeleteObject(regiao as _);
            return;
        }

        // A partir daqui a regiao pertence ao sistema. Liberar seria uso depois de
        // liberado - o Windows a destroi junto com a janela.
        SetWindowRgn(hwnd, regiao, TRUE);
        log::info!("Window shaped with {} rectangles", total);
    }
}

/// Minimiza a janela. Importa mais do que parece: na primeira instalacao o jogador
/// baixa varios GB e vai querer fazer outra coisa enquanto espera.
#[cfg(windows)]
fn handle_minimize() {
    use winapi::um::winuser::{ShowWindow, SW_MINIMIZE};
    if let Some(hwnd) = janela_principal() {
        unsafe {
            ShowWindow(hwnd, SW_MINIMIZE);
        }
    }
}

/// Arrasta a janela pelo ponto onde o jogador clicou.
///
/// O truque e classico: solta a captura do mouse que o MSHTML esta segurando e finge
/// para o Windows que o clique aconteceu na barra de titulo. Ele entao entra sozinho no
/// laco modal de mover a janela, que segue o cursor ate o botao ser solto.
///
/// So funciona chamado com o botao do mouse AINDA PRESSIONADO - por isso a pagina
/// dispara isto no `onmousedown`, e nao no `onclick`.
#[cfg(windows)]
fn handle_drag() {
    use winapi::shared::minwindef::WPARAM;
    use winapi::um::winuser::{ReleaseCapture, SendMessageW, HTCAPTION, WM_NCLBUTTONDOWN};
    if let Some(hwnd) = janela_principal() {
        unsafe {
            ReleaseCapture();
            SendMessageW(hwnd, WM_NCLBUTTONDOWN, HTCAPTION as WPARAM, 0);
        }
    }
}

// Fora do Windows os dois viram nada: o projeto tambem compila para Linux, e la a
// barra de titulo e responsabilidade do gerenciador de janelas.
#[cfg(not(windows))]
fn handle_ajustar_janela(_webview: &mut WebView<WebViewUserData>) {}
#[cfg(not(windows))]
fn handle_moldar_janela() {}
#[cfg(not(windows))]
fn handle_minimize() {}
#[cfg(not(windows))]
fn handle_drag() {}

/// Parses JSON requests (for invoking functions with parameters) and dispatches
/// them to the invoked function.
fn handle_json_request(webview: &mut WebView<WebViewUserData>, request: &str) {
    let result: serde_json::Result<Value> = serde_json::from_str(request);
    match result {
        Err(e) => {
            log::error!("Invalid JSON request: {}", e);
        }
        Ok(json_req) => {
            let function_name = json_req["function"].as_str();
            if let Some(function_name) = function_name {
                let function_params = json_req["parameters"].clone();
                match function_name {
                    "login" => handle_login(webview, function_params),
                    "open_url" => handle_open_url(function_params),
                    _ => {
                        log::error!("Unknown function '{}'", function_name);
                    }
                }
            }
        }
    }
}

/// Parameters expected for the login function
#[derive(Deserialize)]
struct LoginParameters {
    login: String,
    password: String,
}

/// Launches the game client with the given credentials
fn handle_login(webview: &mut WebView<WebViewUserData>, parameters: Value) {
    let result: serde_json::Result<LoginParameters> = serde_json::from_value(parameters);
    match result {
        Err(e) => log::error!("Invalid arguments given for 'login': {}", e),
        Ok(login_params) => {
            // Push credentials to the list of arguments first
            let mut play_arguments: Vec<String> = vec![
                format!("-t:{}", login_params.password),
                login_params.login,
                "server".to_string(),
            ];
            play_arguments.extend(
                webview
                    .user_data()
                    .patcher_config
                    .play
                    .arguments
                    .iter()
                    .cloned(),
            );
            start_game_client(webview, &play_arguments);
        }
    }
}

/// Parameters expected for the open_url function
#[derive(Deserialize)]
struct OpenUrlParameters {
    url: String,
}

/// Opens an URL with the native URL Handler
fn handle_open_url(parameters: Value) {
    let result: serde_json::Result<OpenUrlParameters> = serde_json::from_value(parameters);
    match result {
        Err(e) => log::error!("Invalid arguments given for 'open_url': {}", e),
        Ok(params) => match open::that(params.url) {
            Ok(exit_status) => {
                if !exit_status.success() {
                    if let Some(code) = exit_status.code() {
                        log::error!("Command returned non-zero exit status {}!", code);
                    }
                }
            }
            Err(why) => {
                log::error!("Error open_url function: '{}'", why);
            }
        },
    }
}

fn start_game_client(webview: &mut WebView<WebViewUserData>, client_arguments: &[String]) {
    let client_exe: &String = &webview.user_data().patcher_config.play.path;
    let exit_on_success = webview
        .user_data()
        .patcher_config
        .play
        .exit_on_success
        .unwrap_or(true);
    match start_executable(client_exe, client_arguments) {
        Ok(success) => {
            if success {
                log::trace!("Client started");
                if exit_on_success {
                    webview.exit();
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to start client: {}", e);
        }
    }
}
