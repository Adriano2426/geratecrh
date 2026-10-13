-- ============================================================
-- GERATEC — Fase 2: checklist, anexos multiplos, papel do responsavel
-- (rode no SQL Editor do Supabase)
--
-- ATENCAO: a observacao abaixo estava ERRADA e foi corrigida pelo script
-- supabase_tranca_cofre_e_rls.sql, que liga o RLS nessas duas tabelas.
-- tarefas_comentarios e tarefas_responsaveis TEM RLS ligado; estas duas
-- ficaram sendo as unicas sem, e o Security Advisor passou a apontar as duas
-- como erro critico. Se for recriar o banco do zero, rode o outro script junto.
--
-- (texto original, mantido para registro:)
-- Segue o mesmo nivel de acesso ja usado em tabelas como
-- tarefas_comentarios e tarefas_responsaveis: leitura e escrita
-- liberadas para a chave anon, sem RLS -- nao guardam segredo
-- nenhum (diferente de usuarios/cofre, que ja estao trancados).
-- ============================================================

-- 1) Checklist de subtarefas
create table if not exists public.tarefas_checklist (
  id bigint generated always as identity primary key,
  tarefa_id bigint not null references public.tarefas(id) on delete cascade,
  texto text not null,
  concluido boolean not null default false,
  ordem integer not null default 0,
  criado_em timestamptz not null default now()
);
grant select, insert, update, delete on public.tarefas_checklist to anon;

-- 2) Anexos multiplos por tarefa
create table if not exists public.tarefas_anexos (
  id bigint generated always as identity primary key,
  tarefa_id bigint not null references public.tarefas(id) on delete cascade,
  nome text not null,
  url text not null,
  tipo text,
  criado_por text,
  criado_em timestamptz not null default now()
);
grant select, insert, update, delete on public.tarefas_anexos to anon;

-- 3) Papel do responsavel (principal ou apoio)
alter table public.tarefas_responsaveis add column if not exists papel text not null default 'apoio';
