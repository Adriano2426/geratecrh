-- ============================================================
-- GERATEC — Hardening de acesso (rode no SQL Editor do Supabase)
--
-- Problema que isso resolve: a chave publica do projeto fica
-- exposta no codigo-fonte do site (isso e normal e esperado do
-- Supabase). Ate agora, qualquer pessoa com essa chave conseguia
-- ler a tabela "usuarios" inteira -- inclusive os hashes de senha
-- de todo mundo -- sem fazer login. Confirmado com um curl simples.
--
-- IMPORTANTE: depois de rodar este script, publique a versao mais
-- recente do site (o codigo ja foi ajustado para usar as funcoes
-- abaixo em vez de ler a senha direto da tabela). Rode o script
-- ANTES de publicar o site, senao ninguem consegue logar por uns
-- minutos.
-- ============================================================

-- 1) Impede leitura da coluna "password" pela chave publica (anon).
--    As outras colunas (username, display_name, role, must_change_password)
--    continuam legiveis -- sao usadas pra montar a lista de pessoas do time.
revoke select on public.usuarios from anon;
grant select (username, display_name, role, must_change_password) on public.usuarios to anon;

-- 2) Funcao que verifica login DENTRO do banco.
--    Ela nunca devolve o hash pro navegador -- so diz se bateu ou nao,
--    e devolve os dados necessarios pra abrir a sessao.
create or replace function public.login_check(p_username text, p_password_hash text)
returns table(username text, display_name text, role text, must_change_password boolean)
language sql
security definer
set search_path = public
as $$
  select username, display_name, role, must_change_password
  from public.usuarios
  where username = p_username and password = p_password_hash;
$$;

revoke all on function public.login_check(text, text) from public;
grant execute on function public.login_check(text, text) to anon;

-- ============================================================
-- 3) Cofre de acessos ("Acessos e Senhas") — mais sensivel ainda,
--    porque guarda credenciais reais de sistemas em texto livre.
--
--    ATENCAO / TROCA CONSCIENTE:
--    Isso bloqueia a LEITURA direta das tabelas do cofre pela chave
--    publica. Como o app hoje nao tem um jeito real de provar "quem
--    esta logado" pro banco (nao usa Supabase Auth), nao da pra
--    liberar so pra quem tem permissao sem reescrever a autenticacao
--    inteira. Rodando isso, a tela "Acessos e Senhas" fica vazia /
--    indisponivel ate voces migrarem para Supabase Auth de verdade.
--
--    A alternativa e NAO rodar este bloco e aceitar que qualquer
--    pessoa com a chave publica (visivel no codigo-fonte do site)
--    consegue ler as senhas guardadas ali. Recomendo rodar mesmo
--    assim -- e melhor a funcionalidade ficar indisponivel por um
--    tempo do que vazar credenciais de sistemas.
-- ============================================================
alter table public.cofre_caixas enable row level security;
alter table public.cofre_acessos enable row level security;
revoke select on public.cofre_caixas from anon;
revoke select on public.cofre_acessos from anon;
-- (nenhuma "policy" foi criada de proposito: com RLS ligado e sem
--  policy, o acesso fica bloqueado por padrao para todo mundo)
