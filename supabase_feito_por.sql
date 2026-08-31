-- ============================================================
-- GERATEC — Coluna "feito_por" (quem já entregou a sua parte)
-- (rode no SQL Editor do Supabase)
--
-- Para que serve: numa tarefa com vários responsáveis, quando alguém
-- conclui a parte dela e repassa, o sistema precisa lembrar quem já
-- entregou. Sem isso, ao final a tarefa ficaria oferecendo de volta
-- quem já tinha feito a parte dele, e o repasse poderia ficar girando
-- entre as mesmas pessoas sem nunca fechar.
--
-- Guarda os usernames separados por vírgula (ex.: "ana,marlene").
-- É limpa sozinha quando a tarefa fecha de vez ou é reaberta.
--
-- Enquanto este script não for rodado, o site continua funcionando:
-- ele detecta que a coluna não existe e salva a tarefa sem esse campo
-- (só não lembra quem já entregou entre uma sessão e outra).
-- ============================================================

alter table public.tarefas add column if not exists feito_por text;
