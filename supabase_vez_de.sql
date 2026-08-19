-- ============================================================
-- GERATEC — Coluna "vez_de" (repasse em tarefa compartilhada)
-- (rode no SQL Editor do Supabase)
--
-- Para que serve: quando uma tarefa tem mais de um responsavel, ela
-- nao termina so porque uma pessoa fez a parte dela. Ao marcar como
-- concluida, o site pergunta quem precisa dar andamento; a tarefa
-- vai para "Aguardando terceiros" registrando de quem e a vez.
-- Essa coluna guarda esse "de quem e a vez agora".
--
-- Enquanto este script nao for rodado, o site continua funcionando
-- normalmente — so nao guarda de quem e a vez (ele detecta que a
-- coluna nao existe e salva a tarefa sem esse campo).
-- ============================================================

alter table public.tarefas add column if not exists vez_de text;
