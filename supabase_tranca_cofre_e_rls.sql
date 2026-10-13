-- ============================================================
-- GERATEC — Tranca do cofre + RLS nas tabelas da fase 2
-- (rode no SQL Editor do Supabase, de uma vez)
--
-- RODE A PARTE 1 PRIMEIRO E NO MESMO DIA. A PARTE 2 pode esperar.
--
-- Pre-requisito: o site precisa estar com a versao que NAO assina mais os
-- canais de tempo real do cofre. Se rodar a PARTE 1 numa versao antiga, o
-- indicador de conexao fica ambar ("Sem aviso ao vivo") porque os canais
-- cofre_caixas/cofre_acessos vao falhar ao entrar.
-- ============================================================


-- ============================================================
-- PARTE 1 — URGENTE: o cofre de senhas
--
-- O problema (verificado na base de producao, so com leitura):
--   A chave publicavel do site le a tabela cofre_caixas direto, inclusive a
--   coluna "observacoes" — que e justamente o campo de texto livre onde as
--   senhas sao digitadas. Essa chave esta no codigo-fonte da pagina publicada
--   no GitHub Pages, entao qualquer pessoa que abra o site e olhe o fonte
--   consegue fazer essa leitura. O mesmo vale pra cofre_acessos, que entrega
--   quem tem acesso a quais caixas.
--
--   O Security Advisor NAO aponta isso como erro, porque o RLS esta ligado
--   nessas tabelas. O que esta aberto e a permissao de SELECT da chave anon.
--
-- Por que da pra trancar sem quebrar nada:
--   O site nao le essas tabelas direto. Ele le pelas funcoes get_vault_boxes e
--   get_vault_access, que sao SECURITY DEFINER (rodam com permissao propria) e
--   ja filtram por usuario. A unica coisa que o site faz direto na tabela e
--   excluir uma caixa.
--
--   Por isso o SELECT volta so na coluna "id": no PostgreSQL, um
--   DELETE ... WHERE id = x precisa de SELECT nas colunas usadas no WHERE.
--   Sem isso, excluir caixa pararia de funcionar.
-- ============================================================

-- cofre_caixas: tira a leitura geral, devolve so o id (pro delete funcionar)
revoke select on public.cofre_caixas from anon;
grant  select (id) on public.cofre_caixas to anon;

-- cofre_acessos: o site nunca toca nessa tabela direto, nem pra ler nem pra
-- escrever — tudo passa por create_vault_box / update_vault_box / get_vault_access.
revoke select on public.cofre_acessos from anon;

-- Garante o RLS ligado nas duas (se ja estiver, rodar de novo nao faz mal).
alter table public.cofre_caixas  enable row level security;
alter table public.cofre_acessos enable row level security;


-- ============================================================
-- PARTE 2 — Os dois erros que o Security Advisor aponta
--
-- tarefas_checklist e tarefas_anexos foram criadas sem RLS, de proposito, pelo
-- script supabase_fase2.sql. A premissa daquele script estava errada: ele dizia
-- seguir "o mesmo nivel das tabelas tarefas_comentarios e tarefas_responsaveis",
-- mas essas tem RLS ligado. Essas duas ficaram como as unicas sem.
--
-- SEJA HONESTO SOBRE O QUE ISSO RESOLVE:
--   Ligar o RLS com uma politica permissiva faz o Advisor ficar verde, mas NAO
--   reduz a exposicao real. Como o login do GERATEC e feito no navegador e todo
--   mundo usa a mesma chave publicavel, o banco nao tem como saber quem e quem:
--   nao existe politica mais restritiva possivel sem mudar a arquitetura.
--
--   O ganho verdadeiro aqui e deixar a postura declarada e igual a das outras
--   tabelas, em vez de ser uma excecao silenciosa. Se um dia essas tabelas
--   precisarem valer segredo, o caminho e o mesmo do cofre: fechar o acesso
--   direto e passar por funcoes SECURITY DEFINER.
-- ============================================================

alter table public.tarefas_checklist enable row level security;
alter table public.tarefas_anexos    enable row level security;

drop policy if exists checklist_acesso_app on public.tarefas_checklist;
create policy checklist_acesso_app
  on public.tarefas_checklist
  for all
  to anon
  using (true)
  with check (true);

drop policy if exists anexos_acesso_app on public.tarefas_anexos;
create policy anexos_acesso_app
  on public.tarefas_anexos
  for all
  to anon
  using (true)
  with check (true);


-- ============================================================
-- CONFERENCIA — rode depois e veja se bate com o esperado
-- ============================================================

-- Esperado: cofre_caixas so com "id", cofre_acessos sem nenhuma linha de select.
select table_name, column_name, privilege_type
from information_schema.column_privileges
where grantee = 'anon'
  and table_schema = 'public'
  and table_name in ('cofre_caixas','cofre_acessos')
  and privilege_type = 'SELECT'
order by table_name, column_name;

-- Esperado: rowsecurity = true nas quatro.
select relname as tabela, relrowsecurity as rls_ligado
from pg_class
where relnamespace = 'public'::regnamespace
  and relname in ('cofre_caixas','cofre_acessos','tarefas_checklist','tarefas_anexos')
order by relname;
