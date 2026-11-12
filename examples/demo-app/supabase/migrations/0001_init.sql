-- Demo app: deliberately insecure. Do not deploy.
create table public.projects (
  id bigint generated always as identity primary key,
  owner uuid references auth.users not null,
  name text not null,
  summary text
);
alter table public.projects enable row level security;

-- Turns RLS on, then lets anyone change any project.
create policy "projects are editable" on public.projects
  for update using (true);

-- No Row Level Security at all: the anon key can read and write every invoice.
create table public.invoices (
  id bigint generated always as identity primary key,
  project_id bigint references public.projects,
  amount_cents integer not null,
  paid boolean default false
);
