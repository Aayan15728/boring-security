create table users (
  id bigserial primary key,
  email text not null unique,
  password_hash text not null,
  created_at timestamptz not null default now()
);

create table notes (
  id bigserial primary key,
  owner_id bigint not null references users (id) on delete cascade,
  title text not null check (length(title) between 1 and 200),
  body text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index notes_owner_created_idx on notes (owner_id, created_at desc);

create table webhook_events (
  id text primary key,
  type text not null,
  received_at timestamptz not null default now()
);
