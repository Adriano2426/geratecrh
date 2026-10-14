-- ============================================================
-- GERATEC — Diagnostico de seguranca (SO LEITURA)
--
-- Este script NAO altera nada. Sao quatro consultas que reproduzem o que o
-- Security Advisor do Supabase verifica. Rode no SQL Editor e me mande o
-- resultado das quatro — com isso eu escrevo a correcao sabendo o que estou
-- corrigindo, em vez de adivinhar.
--
-- Pode rodar tudo de uma vez: o SQL Editor mostra um resultado por consulta.
-- ============================================================


-- ------------------------------------------------------------
-- 1) Tabelas: RLS ligado? quantas politicas cada uma tem?
--
-- O que procurar:
--   rls_ligado = false            -> erro critico (porta aberta)
--   rls_ligado = true, politicas = 0 -> warning "RLS Enabled No Policy"
--      (nesse caso quem decide o acesso e so o GRANT, nao a politica)
-- ------------------------------------------------------------
select c.relname                                                      as tabela,
       c.relrowsecurity                                               as rls_ligado,
       (select count(*) from pg_policy p where p.polrelid = c.oid)    as politicas,
       has_table_privilege('anon', c.oid, 'SELECT')                   as anon_le,
       has_table_privilege('anon', c.oid, 'INSERT')                   as anon_insere,
       has_table_privilege('anon', c.oid, 'UPDATE')                   as anon_altera,
       has_table_privilege('anon', c.oid, 'DELETE')                   as anon_apaga
from pg_class c
where c.relnamespace = 'public'::regnamespace
  and c.relkind = 'r'
order by c.relrowsecurity, c.relname;


-- ------------------------------------------------------------
-- 2) Funcoes: quais rodam com permissao propria e com que search_path
--
-- O que procurar:
--   security_definer = true e config = null -> warning "Function Search Path
--   Mutable". As cinco funcoes do GERATEC ja devem aparecer com
--   {search_path=public}, entao qualquer outra linha aqui e novidade.
-- ------------------------------------------------------------
select p.proname                                   as funcao,
       pg_get_function_identity_arguments(p.oid)   as argumentos,
       p.prosecdef                                 as security_definer,
       p.proconfig                                 as config
from pg_proc p
where p.pronamespace = 'public'::regnamespace
order by p.prosecdef desc, p.proname;


-- ------------------------------------------------------------
-- 3) Views: alguma roda com permissao do dono em vez da de quem consulta?
--
-- O que procurar: qualquer linha aqui ja merece olhada. Uma view sem
-- security_invoker=true roda com a permissao de quem a criou, o que pode
-- furar o RLS das tabelas por baixo dela.
-- ------------------------------------------------------------
select c.relname      as view_nome,
       c.reloptions   as opcoes
from pg_class c
where c.relnamespace = 'public'::regnamespace
  and c.relkind in ('v', 'm')
order by c.relname;


-- ------------------------------------------------------------
-- 4) Extensoes instaladas fora do lugar
--
-- O que procurar: extensao com schema = public -> warning "Extension in
-- Public". Nao e grave, mas e um dos avisos mais comuns.
-- ------------------------------------------------------------
select e.extname    as extensao,
       n.nspname    as schema
from pg_extension e
join pg_namespace n on n.oid = e.extnamespace
order by n.nspname, e.extname;
