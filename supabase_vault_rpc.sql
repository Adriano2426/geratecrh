-- ============================================================
-- GERATEC — Restaura o cofre de acessos usando funcoes no banco
-- (rode no SQL Editor do Supabase, DEPOIS do supabase_hardening.sql)
--
-- Contexto: o supabase_hardening.sql bloqueou a leitura direta do
-- cofre pela chave publica (correto, porque guarda credenciais de
-- sistemas). Isso deixou a tela "Acessos e Senhas" indisponivel.
-- Este script devolve a funcionalidade usando funcoes que aplicam,
-- dentro do banco, a mesma regra que o app ja usava: mostra a caixa
-- se ela for "geral", se a pessoa foi quem criou, se a pessoa esta
-- na lista de acesso restrito, ou se a pessoa e admin.
--
-- LIMITE HONESTO: como o app nao usa Supabase Auth (nao ha um jeito
-- do banco confirmar de verdade "quem esta perguntando"), o
-- "p_username" enviado e uma informacao que o proprio site informa,
-- do mesmo jeito que ja acontece em todo o resto do app (por
-- exemplo, quem e admin). Isso fecha o problema de qualquer pessoa
-- no mundo conseguir ler o cofre sem nem abrir o site, mas nao e
-- uma prova criptografica de identidade -- isso so viria com uma
-- migracao para Supabase Auth.
-- ============================================================

-- 1) Leitura das caixas visiveis para quem esta perguntando
create or replace function public.get_vault_boxes(p_username text)
returns setof public.cofre_caixas
language sql
security definer
set search_path = public
as $$
  select cc.*
  from public.cofre_caixas cc
  where cc.acesso = 'geral'
     or cc.criado_por = p_username
     or exists (
       select 1 from public.cofre_acessos ca
       where ca.caixa_id = cc.id and ca.username = p_username
     )
     or exists (
       select 1 from public.usuarios u where u.username = p_username and u.role = 'admin'
     );
$$;
revoke all on function public.get_vault_boxes(text) from public;
grant execute on function public.get_vault_boxes(text) to anon;

-- 2) Lista de quem tem acesso a cada caixa restrita visivel (pra montar os chips de "quem pode ver")
create or replace function public.get_vault_access(p_username text)
returns setof public.cofre_acessos
language sql
security definer
set search_path = public
as $$
  select ca.*
  from public.cofre_acessos ca
  where ca.caixa_id in (select id from public.get_vault_boxes(p_username));
$$;
revoke all on function public.get_vault_access(text) from public;
grant execute on function public.get_vault_access(text) to anon;

-- 3) Criar caixa (insere a caixa e a lista de acesso restrito em uma so operacao)
create or replace function public.create_vault_box(
  p_titulo text, p_cor text, p_observacoes text, p_criado_por text,
  p_acesso text, p_selected_usernames text[]
) returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  new_id bigint;
begin
  insert into public.cofre_caixas (titulo, cor, observacoes, criado_por, acesso)
  values (p_titulo, p_cor, p_observacoes, p_criado_por, p_acesso)
  returning id into new_id;

  if p_acesso = 'restrito' and p_selected_usernames is not null and array_length(p_selected_usernames,1) > 0 then
    insert into public.cofre_acessos (caixa_id, username)
    select new_id, u from unnest(p_selected_usernames) as u;
  end if;
end;
$$;
revoke all on function public.create_vault_box(text,text,text,text,text,text[]) from public;
grant execute on function public.create_vault_box(text,text,text,text,text,text[]) to anon;

-- 4) Editar caixa (atualiza dados e substitui a lista de acesso restrito)
create or replace function public.update_vault_box(
  p_id bigint, p_titulo text, p_cor text, p_observacoes text,
  p_acesso text, p_selected_usernames text[]
) returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.cofre_caixas
  set titulo = p_titulo, cor = p_cor, observacoes = p_observacoes, acesso = p_acesso
  where id = p_id;

  delete from public.cofre_acessos where caixa_id = p_id;
  if p_acesso = 'restrito' and p_selected_usernames is not null and array_length(p_selected_usernames,1) > 0 then
    insert into public.cofre_acessos (caixa_id, username)
    select p_id, u from unnest(p_selected_usernames) as u;
  end if;
end;
$$;
revoke all on function public.update_vault_box(bigint,text,text,text,text,text[]) from public;
grant execute on function public.update_vault_box(bigint,text,text,text,text,text[]) to anon;
