-- ============================================================
-- GERATEC — Cofre com token de sessao
-- (rode no SQL Editor do Supabase)
--
-- O PROBLEMA QUE ISSO RESOLVE
--   As funcoes do cofre recebiam o nome do usuario como parametro e
--   acreditavam nele. Como a lista de usuarios e publica e a chave do site
--   esta no codigo-fonte da pagina, qualquer pessoa conseguia:
--     1. ler os 12 nomes em /rest/v1/usuarios?select=username
--     2. chamar /rest/v1/rpc/get_vault_boxes com {"p_username":"helena"}
--     3. receber as caixas de volta, com a coluna "observacoes"
--   Sem senha nenhuma. Verificado na base de producao em 14/10/2026.
--
-- COMO PASSA A FUNCIONAR
--   O login devolve um token aleatorio de 256 bits, guardado na tabela
--   usuarios com validade. As funcoes do cofre passam a receber o TOKEN, e
--   nao o nome: quem e o usuario e deduzido do token. Nao da pra forjar sem
--   ter feito login com a senha certa.
--
--   A validade e renovada a cada leitura do cofre (7 dias deslizantes), pra
--   quem usa o sistema todo dia nunca ser expulso.
--
-- ORDEM DE EXECUCAO — IMPORTANTE
--   PARTE A: rode agora. So adiciona coisas; o site atual continua
--            funcionando normalmente enquanto isso.
--   Depois:  confirme que o site novo esta no ar e que a aba
--            "Acessos e Senhas" abre, e que voce consegue criar/editar caixa.
--   PARTE B: rode por ultimo. E ela que fecha o buraco de verdade,
--            removendo as funcoes antigas. Ate rodar a PARTE B o buraco
--            continua aberto.
-- ============================================================


-- ============================================================
-- PARTE A — adiciona o token e as funcoes novas (nao remove nada)
-- ============================================================

-- A1) Onde o token mora.
-- A chave publica nao enxerga estas colunas: o supabase_hardening.sql deixou
-- o select de "usuarios" liberado apenas para 4 colunas nominais, e colunas
-- novas nao entram nesse grant. O revoke abaixo e so cinto e suspensorio.
alter table public.usuarios add column if not exists session_token     text;
alter table public.usuarios add column if not exists session_token_exp timestamptz;

revoke select (session_token, session_token_exp) on public.usuarios from anon;

create index if not exists usuarios_session_token_idx
  on public.usuarios (session_token)
  where session_token is not null;


-- A2) Login que emite o token.
-- Mesma verificacao de antes (usuario + hash da senha), mas agora devolve
-- tambem um token. Usa gen_random_uuid(), que vive no pg_catalog e nao
-- depende de extensao instalada em schema nenhum.
create or replace function public.login_check_v2(p_username text, p_password_hash text)
returns table(username text, display_name text, role text,
              must_change_password boolean, session_token text)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user  public.usuarios%rowtype;
  v_token text;
begin
  select * into v_user
  from public.usuarios u
  where u.username = p_username and u.password = p_password_hash;

  if not found then
    return;  -- zero linhas, igual a versao antiga fazia
  end if;

  v_token := replace(gen_random_uuid()::text, '-', '')
          || replace(gen_random_uuid()::text, '-', '');

  update public.usuarios u
     set session_token     = v_token,
         session_token_exp = now() + interval '7 days'
   where u.username = p_username;

  return query
    select v_user.username, v_user.display_name, v_user.role,
           v_user.must_change_password, v_token;
end;
$$;

revoke all     on function public.login_check_v2(text, text) from public;
grant  execute on function public.login_check_v2(text, text) to anon;


-- A3) Quem e o dono deste token? (uso interno — a chave publica nao chama)
create or replace function public.vault_user_from_token(p_token text)
returns text
language sql
stable
security definer
set search_path = public
as $$
  select u.username
  from public.usuarios u
  where p_token is not null
    and length(p_token) = 64
    and u.session_token = p_token
    and u.session_token_exp > now();
$$;

revoke all on function public.vault_user_from_token(text) from public;
-- sem grant para anon de proposito: so as funcoes abaixo usam.


-- A4) Leitura das caixas. Renova a validade do token a cada uso.
create or replace function public.vault_boxes(p_token text)
returns setof public.cofre_caixas
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user text;
begin
  v_user := public.vault_user_from_token(p_token);
  if v_user is null then
    -- Erro explicito em vez de lista vazia: senao a tela diria "nenhuma caixa
    -- visivel para voce", que e indistinguivel de uma sessao vencida.
    raise exception 'sessao invalida ou vencida';
  end if;

  update public.usuarios u
     set session_token_exp = now() + interval '7 days'
   where u.username = v_user;

  return query
    select cc.*
    from public.cofre_caixas cc
    where cc.acesso = 'geral'
       or cc.criado_por = v_user
       or exists (select 1 from public.cofre_acessos ca
                   where ca.caixa_id = cc.id and ca.username = v_user)
       or exists (select 1 from public.usuarios u
                   where u.username = v_user and u.role = 'admin');
end;
$$;

revoke all     on function public.vault_boxes(text) from public;
grant  execute on function public.vault_boxes(text) to anon;


-- A5) Quem tem acesso a cada caixa visivel (monta os chips de "quem pode ver")
create or replace function public.vault_access(p_token text)
returns setof public.cofre_acessos
language sql
security definer
set search_path = public
as $$
  select ca.*
  from public.cofre_acessos ca
  where ca.caixa_id in (select id from public.vault_boxes(p_token));
$$;

revoke all     on function public.vault_access(text) from public;
grant  execute on function public.vault_access(text) to anon;


-- A6) Criar caixa. O "criado_por" vem do token, nao de um parametro:
-- assim ninguem cria caixa no nome de outra pessoa.
create or replace function public.vault_create_box(
  p_token text, p_titulo text, p_cor text, p_observacoes text,
  p_acesso text, p_selected_usernames text[]
) returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user text;
  new_id bigint;
begin
  v_user := public.vault_user_from_token(p_token);
  if v_user is null then
    raise exception 'sessao invalida ou vencida';
  end if;

  insert into public.cofre_caixas (titulo, cor, observacoes, criado_por, acesso)
  values (p_titulo, p_cor, p_observacoes, v_user, p_acesso)
  returning id into new_id;

  if p_acesso = 'restrito'
     and p_selected_usernames is not null
     and array_length(p_selected_usernames, 1) > 0 then
    insert into public.cofre_acessos (caixa_id, username)
    select new_id, u from unnest(p_selected_usernames) as u;
  end if;
end;
$$;

revoke all     on function public.vault_create_box(text,text,text,text,text,text[]) from public;
grant  execute on function public.vault_create_box(text,text,text,text,text,text[]) to anon;


-- A7) Editar caixa. Alem do token, confere que a caixa e visivel pra essa
-- pessoa — a funcao antiga deixava qualquer um editar qualquer caixa.
create or replace function public.vault_update_box(
  p_token text, p_id bigint, p_titulo text, p_cor text, p_observacoes text,
  p_acesso text, p_selected_usernames text[]
) returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user text;
begin
  v_user := public.vault_user_from_token(p_token);
  if v_user is null then
    raise exception 'sessao invalida ou vencida';
  end if;

  if not exists (select 1 from public.vault_boxes(p_token) b where b.id = p_id) then
    raise exception 'sem permissao nessa caixa';
  end if;

  update public.cofre_caixas
     set titulo = p_titulo, cor = p_cor,
         observacoes = p_observacoes, acesso = p_acesso
   where id = p_id;

  delete from public.cofre_acessos where caixa_id = p_id;

  if p_acesso = 'restrito'
     and p_selected_usernames is not null
     and array_length(p_selected_usernames, 1) > 0 then
    insert into public.cofre_acessos (caixa_id, username)
    select p_id, u from unnest(p_selected_usernames) as u;
  end if;
end;
$$;

revoke all     on function public.vault_update_box(text,bigint,text,text,text,text,text[]) from public;
grant  execute on function public.vault_update_box(text,bigint,text,text,text,text,text[]) to anon;


-- A8) Excluir caixa. Hoje o site apaga direto na tabela, o que significa que
-- qualquer um com a chave publica consegue apagar qualquer caixa. Passando
-- por aqui, a exclusao tambem exige token e permissao.
create or replace function public.vault_delete_box(p_token text, p_id bigint)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user text;
begin
  v_user := public.vault_user_from_token(p_token);
  if v_user is null then
    raise exception 'sessao invalida ou vencida';
  end if;

  if not exists (select 1 from public.vault_boxes(p_token) b where b.id = p_id) then
    raise exception 'sem permissao nessa caixa';
  end if;

  delete from public.cofre_caixas where id = p_id;
end;
$$;

revoke all     on function public.vault_delete_box(text, bigint) from public;
grant  execute on function public.vault_delete_box(text, bigint) to anon;


-- ============================================================
-- PARAR AQUI.
--
-- Avise que a PARTE A rodou. Eu confirmo que o site novo esta no ar, voce
-- testa a aba "Acessos e Senhas" (abrir, criar, editar, excluir) e so entao
-- roda a PARTE B abaixo.
-- ============================================================


-- ============================================================
-- PARTE B — fecha o buraco (rode so depois do teste)
--
-- Remove as funcoes que acreditavam no nome enviado e corta o que sobrou de
-- acesso direto da chave publica as tabelas do cofre.
-- ============================================================

-- B1) Fora as funcoes que podiam ser chamadas em nome de qualquer um.
drop function if exists public.get_vault_boxes(text);
drop function if exists public.get_vault_access(text);
drop function if exists public.create_vault_box(text,text,text,text,text,text[]);
drop function if exists public.update_vault_box(bigint,text,text,text,text,text[]);

-- B2) O login antigo nao emite token; sai junto pra ninguem cair nele.
drop function if exists public.login_check(text, text);

-- B3) A exclusao agora passa por funcao, entao a chave publica nao precisa
-- mais de acesso nenhum as tabelas do cofre.
revoke all on public.cofre_caixas  from anon;
revoke all on public.cofre_acessos from anon;

-- B4) As politicas "allow all" dessas duas tabelas deixam de fazer sentido:
-- sem grant nenhum, elas nunca sao alcancadas. Sao removidas para o cofre
-- nao reabrir sozinho se alguem clicar em "enable read access" no painel.
drop policy if exists "allow all cofre_caixas"  on public.cofre_caixas;
drop policy if exists "allow all cofre_acessos" on public.cofre_acessos;


-- ============================================================
-- CONFERENCIA — rode depois da PARTE B
-- ============================================================

-- Esperado: nenhuma linha (as quatro funcoes antigas sumiram).
select p.proname, pg_get_function_identity_arguments(p.oid) as args
from pg_proc p
where p.pronamespace = 'public'::regnamespace
  and p.proname in ('get_vault_boxes','get_vault_access',
                    'create_vault_box','update_vault_box','login_check');

-- Esperado: nenhuma linha (anon sem permissao nas tabelas do cofre).
select table_name, privilege_type
from information_schema.table_privileges
where grantee = 'anon' and table_schema = 'public'
  and table_name in ('cofre_caixas','cofre_acessos');

-- Esperado: nenhuma linha (politicas permissivas do cofre removidas).
select c.relname as tabela, pol.polname as politica
from pg_policy pol join pg_class c on c.oid = pol.polrelid
where c.relname in ('cofre_caixas','cofre_acessos');
