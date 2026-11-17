create table public.support_tickets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles (id),
  email text not null,
  subject text not null,
  body text not null,
  status text not null default 'open',
  created_at timestamptz not null default now()
);

create index support_tickets_user_id_idx on public.support_tickets (user_id);

create table public.email_events (
  id bigint generated always as identity primary key,
  provider_message_id text not null,
  event_type text not null,
  recipient text not null,
  received_at timestamptz not null default now()
);

alter table public.email_events enable row level security;
