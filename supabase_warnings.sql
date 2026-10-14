-- ============================================================
-- GERATEC — Limpeza dos warnings do Security Advisor
-- (rode no SQL Editor do Supabase)
--
-- Ponto de partida: 28 warnings em 14/10/2026.
-- Depois deste script: 13.
--
-- Os 15 que saem, saem por motivo real — nenhum e maquiagem:
--    7  funcoes deixam de ser chamaveis pelo papel "authenticated"
--    1  vault_user_from_token deixa de ser chamavel pela chave publica
--    6  tabelas da aba desativada perdem politica e permissao
--    1  o bucket para de permitir listar todos os arquivos
--
-- Os 13 que ficam estao explicados no fim do arquivo. Eles sao consequencia
-- de o login do GERATEC acontecer no navegador com uma chave compartilhada:
-- nao ha como o banco distinguir uma pessoa da outra. Sumir com eles exige
-- migrar para Supabase Auth, que e outro projeto.
--
-- PRE-REQUISITO: o site precisa estar com a versao que nao le mais as tabelas
-- do mural / informacoes gerais. Sem ela, a PARTE 4 derruba o app para o modo
-- local. Confirme comigo antes de rodar a PARTE 4.
-- ============================================================


-- ============================================================
-- ANTES DE TUDO: guarde a definicao da politica do bucket
--
-- Copie o resultado disto e guarde. Se os anexos pararem de abrir depois da
-- PARTE 3, e com isso que a politica e recriada.
-- ============================================================
select pol.polname                               as politica,
       pg_get_expr(pol.polqual, pol.polrelid)    as condicao_using,
       pol.polroles::regrole[]                   as papeis,
       pol.polcmd                                as comando
from pg_policy pol
where pol.polrelid = 'storage.objects'::regclass;


-- ============================================================
-- PARTE 1 — Tirar as funcoes do alcance do papel "authenticated"
--
-- O GERATEC nao usa Supabase Auth: ninguem nunca e "authenticated" neste
-- projeto. Essas permissoes existem so porque o Supabase concede EXECUTE a
-- anon e authenticated por padrao em toda funcao nova do schema public.
-- Revogar nao tem efeito nenhum no funcionamento e resolve 7 warnings.
-- ============================================================

revoke execute on function public.login_check_v2(text, text)                                      from authenticated;
revoke execute on function public.vault_boxes(text)                                               from authenticated;
revoke execute on function public.vault_access(text)                                              from authenticated;
revoke execute on function public.vault_create_box(text,text,text,text,text,text[])               from authenticated;
revoke execute on function public.vault_update_box(text,bigint,text,text,text,text,text[])        from authenticated;
revoke execute on function public.vault_delete_box(text, bigint)                                  from authenticated;
revoke execute on function public.vault_user_from_token(text)                                     from authenticated;


-- ============================================================
-- PARTE 2 — vault_user_from_token sai do alcance da chave publica
--
-- Esta e uma funcao de uso interno: as outras do cofre a usam pra descobrir
-- de quem e o token. O script anterior tentou fecha-la com
-- "revoke all ... from public", mas isso nao bastou: o Supabase concede
-- EXECUTE DIRETAMENTE ao papel anon por padrao, e revogar de "public" nao
-- mexe num grant nominal. Verificado: chamando /rest/v1/rpc/vault_user_from_token
-- com a chave publica, ela respondia (devolvia null) em vez de recusar.
--
-- Na pratica nao vazava muito (sem um token valido de 64 caracteres ela nao
-- diz nada), mas era um oraculo desnecessario: dado um token, dizia de quem e.
-- ============================================================

revoke execute on function public.vault_user_from_token(text) from anon;


-- ============================================================
-- PARTE 3 — O bucket para de deixar listar todos os arquivos
--
-- O bucket "mural-anexos" guarda os anexos do mural E os anexos das tarefas.
-- Ele e publico, o que ja significa que quem tem a URL de um arquivo abre o
-- arquivo. O problema e outro: a politica ampla de SELECT deixa qualquer um
-- LISTAR o bucket inteiro e descobrir todos os arquivos que existem, sem
-- precisar conhecer URL nenhuma.
--
-- Bucket publico nao precisa dessa politica pra servir arquivo por URL: isso
-- passa por /storage/v1/object/public/..., que nao consulta a politica.
--
-- TESTE DEPOIS DE RODAR: abra uma tarefa que tenha anexo e clique no arquivo.
-- Se nao abrir, recrie a politica com o que voce copiou la em cima.
-- ============================================================

drop policy if exists "mural anexos leitura" on storage.objects;


-- ============================================================
-- PARTE 4 — Tabelas da aba "Informacoes Gerais", que esta desativada
--
-- A aba foi desligada no site (mural e caixas de conversa nao sao usados) e
-- as seis tabelas estao vazias — conferido: zero linhas em todas. Hoje elas
-- tem politica "allow all", ou seja, qualquer pessoa com a chave publica
-- pode ler, escrever e apagar nelas.
--
-- Como a funcionalidade esta desligada, o certo e fechar: tirar a politica
-- permissiva e a permissao. Resolve 6 warnings e fecha 6 tabelas que hoje
-- sao graváveis pelo mundo inteiro.
--
-- PARA REATIVAR A ABA NO FUTURO: alem de voltar ABA_INFO_ATIVA para true no
-- index.html, e preciso desfazer esta parte — devolver o grant e recriar as
-- politicas. Esta anotado no fim do arquivo.
--
-- NAO RODE ANTES de o site novo estar publicado: a versao antiga le essas
-- tabelas sem protecao de erro, e a leitura falhando derruba o app inteiro
-- para o modo local.
-- ============================================================

drop policy if exists "allow all info_caixas"          on public.info_caixas;
drop policy if exists "allow all info_caixas_acessos"  on public.info_caixas_acessos;
drop policy if exists "allow all info_mensagens"       on public.info_mensagens;
drop policy if exists "allow all mural_posts"          on public.mural_posts;
drop policy if exists "allow all mural_reacoes"        on public.mural_reacoes;
drop policy if exists "allow all mural_visualizacoes"  on public.mural_visualizacoes;

revoke all on public.info_caixas          from anon;
revoke all on public.info_caixas_acessos  from anon;
revoke all on public.info_mensagens       from anon;
revoke all on public.mural_posts          from anon;
revoke all on public.mural_reacoes        from anon;
revoke all on public.mural_visualizacoes  from anon;


-- ============================================================
-- CONFERENCIA
-- ============================================================

-- Esperado: so anon em login_check_v2, vault_boxes, vault_access,
-- vault_create_box, vault_update_box, vault_delete_box. Nada de
-- vault_user_from_token e nada de authenticated.
select p.proname                                  as funcao,
       r.rolname                                  as papel
from pg_proc p
cross join lateral (values ('anon'), ('authenticated')) as x(rolname)
join pg_roles r on r.rolname = x.rolname
where p.pronamespace = 'public'::regnamespace
  and has_function_privilege(r.rolname, p.oid, 'EXECUTE')
order by p.proname, r.rolname;

-- Esperado: nenhuma linha das seis tabelas da aba desativada.
select table_name, privilege_type
from information_schema.table_privileges
where grantee = 'anon' and table_schema = 'public'
  and table_name in ('info_caixas','info_caixas_acessos','info_mensagens',
                     'mural_posts','mural_reacoes','mural_visualizacoes');


-- ============================================================
-- OS 13 QUE FICAM, E POR QUE
--
-- 7x "RLS Policy Always True" — tarefas, tarefas_responsaveis,
--    tarefas_comentarios, tarefas_checklist, tarefas_anexos, tarefas_log,
--    usuarios. Sao as tabelas que o site usa o tempo todo. A politica e
--    "allow all" porque nao existe politica mais restritiva possivel: o
--    login acontece no navegador e todo mundo usa a mesma chave, entao o
--    banco nao tem como saber se quem esta pedindo e a Daniele ou a Marlene.
--    Escrever qualquer condicao aqui seria teatro.
--
-- 6x "Public Can Execute SECURITY DEFINER Function" — login_check_v2 e as
--    cinco funcoes do cofre. Elas PRECISAM ser chamaveis pela chave publica:
--    e assim que o site inteiro funciona, e login_check_v2 em especial tem
--    que ser aberta ou ninguem consegue entrar. O que protege o cofre nao e
--    esconder a funcao, e ela exigir um token valido — e isso ja esta feito.
--
-- O caminho para zerar os 13 e um so: migrar a autenticacao para o Supabase
-- Auth, para o banco passar a saber quem esta perguntando. Ai as politicas
-- "allow all" viram politicas de verdade ("so quem e responsavel pela tarefa
-- pode altera-la") e as funcoes do cofre deixam de precisar de token proprio.
-- E um projeto a parte, nao um remendo.
-- ============================================================


-- ============================================================
-- DESFAZER A PARTE 4 (so se a aba "Informacoes Gerais" for reativada)
--
-- grant select, insert, update, delete on public.info_caixas         to anon;
-- grant select, insert, update, delete on public.info_caixas_acessos to anon;
-- grant select, insert, update, delete on public.info_mensagens      to anon;
-- grant select, insert, update, delete on public.mural_posts         to anon;
-- grant select, insert, update, delete on public.mural_reacoes       to anon;
-- grant select, insert, update, delete on public.mural_visualizacoes to anon;
--
-- create policy "allow all info_caixas"         on public.info_caixas         for all using (true) with check (true);
-- create policy "allow all info_caixas_acessos" on public.info_caixas_acessos for all using (true) with check (true);
-- create policy "allow all info_mensagens"      on public.info_mensagens      for all using (true) with check (true);
-- create policy "allow all mural_posts"         on public.mural_posts         for all using (true) with check (true);
-- create policy "allow all mural_reacoes"       on public.mural_reacoes       for all using (true) with check (true);
-- create policy "allow all mural_visualizacoes" on public.mural_visualizacoes for all using (true) with check (true);
-- ============================================================
