//! Protecao contra reenvio de ticket.
//!
//! Um ticket vale 30 segundos. Dentro dessa janela, quem capturar os 148 bytes
//! na rede pode tentar reapresenta-los. O HMAC continua conferindo - ele e o
//! mesmo ticket, afinal. O que barra o reenvio e lembrar que aquele `nonce` ja
//! passou por aqui.

use crate::version::TICKET_NONCE_LEN;

/// O que o verificador precisa de um cache de replay.
pub trait ReplayGuard {
    /// Registra o `nonce` se ele for inedito.
    ///
    /// Devolve `true` quando o ticket pode seguir (nonce novo) e `false` quando
    /// ja tinha sido visto.
    ///
    /// `keep_until_ms` e ate quando vale a pena lembrar dele - depois disso o
    /// ticket expirou de qualquer jeito e a entrada so ocupa espaco.
    fn check_and_insert(
        &mut self,
        nonce: &[u8; TICKET_NONCE_LEN],
        keep_until_ms: u64,
        now_ms: u64,
    ) -> bool;
}

/// Cache em memoria, com expiracao e teto de ocupacao.
///
/// 16 bytes de nonce + 8 de prazo por entrada. Um servidor com pico de 500
/// logins por minuto e ticket de 30 s guarda umas 250 entradas ao mesmo tempo -
/// alguns kilobytes. A recomendacao do RSE_SPEC (capacidade >= 4x o pico por
/// minuto) e folgada de proposito.
#[derive(Debug)]
pub struct MemoryReplayGuard {
    entries: Vec<([u8; TICKET_NONCE_LEN], u64)>,
    capacity: usize,
    last_sweep_ms: u64,
}

impl MemoryReplayGuard {
    pub fn new(capacity: usize) -> Self {
        MemoryReplayGuard {
            entries: Vec::new(),
            capacity: capacity.max(16),
            last_sweep_ms: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove o que ja expirou.
    ///
    /// Chamado no maximo uma vez por segundo - varrer a cada login seria
    /// trabalho repetido a toa no caminho mais quente do servidor.
    fn sweep(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.last_sweep_ms) < 1_000 && self.entries.len() < self.capacity {
            return;
        }
        self.last_sweep_ms = now_ms;
        self.entries.retain(|(_, until)| *until > now_ms);
    }
}

impl ReplayGuard for MemoryReplayGuard {
    fn check_and_insert(
        &mut self,
        nonce: &[u8; TICKET_NONCE_LEN],
        keep_until_ms: u64,
        now_ms: u64,
    ) -> bool {
        self.sweep(now_ms);

        if self
            .entries
            .iter()
            .any(|(n, until)| n == nonce && *until > now_ms)
        {
            return false;
        }

        if self.entries.len() >= self.capacity {
            // 🚨 DECISAO DELIBERADA: cheio e sem nada expirado, RECUSA.
            //
            // A alternativa - descartar a entrada mais antiga para abrir espaco -
            // transformaria o cache numa porta: bastaria inundar o servidor com
            // tickets validos para empurrar um nonce especifico para fora e
            // reusa-lo em seguida. Recusar e um erro visivel que aparece no log
            // e no monitoramento; esquecer em silencio e um buraco que ninguem
            // descobre.
            //
            // Se isto aparecer em producao, a capacidade esta pequena para o
            // pico de login - e essa e uma informacao que voce QUER ter.
            return false;
        }

        self.entries.push((*nonce, keep_until_ms));
        true
    }
}

/// Guarda que aceita tudo. **Somente para teste e para o modo `off`.**
#[derive(Debug)]
pub struct NoReplayGuard;

impl ReplayGuard for NoReplayGuard {
    fn check_and_insert(&mut self, _n: &[u8; TICKET_NONCE_LEN], _k: u64, _now: u64) -> bool {
        true
    }
}

#[cfg(test)]
// Em teste, `expect` e `assert` sao a ferramenta certa: falha de teste DEVE
// abortar com mensagem. A proibicao de panico vale para o codigo que roda
// dentro do processo do jogo, nao para o que roda no CI.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn primeiro_passa_segundo_nao() {
        let mut g = MemoryReplayGuard::new(32);
        let n = [1u8; TICKET_NONCE_LEN];
        assert!(g.check_and_insert(&n, 1_000, 0));
        assert!(!g.check_and_insert(&n, 1_000, 0));
    }

    #[test]
    fn expirado_libera_o_nonce() {
        let mut g = MemoryReplayGuard::new(32);
        let n = [2u8; TICKET_NONCE_LEN];
        assert!(g.check_and_insert(&n, 1_000, 0));
        // depois do prazo, a entrada some e o nonce poderia voltar - mas o
        // ticket correspondente ja expirou, entao nao ha o que reusar
        assert!(g.check_and_insert(&n, 3_000, 2_000));
        assert_eq!(g.len(), 1);
    }

    #[test]
    fn nao_cresce_sem_limite() {
        let mut g = MemoryReplayGuard::new(64);
        for i in 0..500u32 {
            let mut n = [0u8; TICKET_NONCE_LEN];
            n[..4].copy_from_slice(&i.to_le_bytes());
            g.check_and_insert(&n, 30_000, 0);
        }
        assert!(g.len() <= 64, "cache passou da capacidade: {}", g.len());
    }

    #[test]
    fn varredura_recupera_espaco() {
        let mut g = MemoryReplayGuard::new(64);
        for i in 0..64u32 {
            let mut n = [0u8; TICKET_NONCE_LEN];
            n[..4].copy_from_slice(&i.to_le_bytes());
            assert!(g.check_and_insert(&n, 30_000, 0));
        }
        // cheio
        assert!(!g.check_and_insert(&[0xFF; TICKET_NONCE_LEN], 30_000, 0));
        // passado o prazo de todos, volta a aceitar
        assert!(g.check_and_insert(&[0xFF; TICKET_NONCE_LEN], 90_000, 40_000));
    }
}
