create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles (id),
  status text not null default 'pending' check (status in ('pending', 'paid', 'shipped', 'refunded')),
  total_cents integer not null,
  shipping_address jsonb,
  paid_at timestamptz,
  created_at timestamptz not null default now()
);

create table public.order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders (id) on delete cascade,
  product_id uuid not null references public.products (id),
  quantity integer not null check (quantity > 0),
  unit_price_cents integer not null
);

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders (id),
  user_id uuid not null references public.profiles (id),
  amount_cents integer not null,
  issued_at timestamptz not null default now()
);

create table public.chat_messages (
  id bigint generated always as identity primary key,
  user_id uuid references public.profiles (id),
  role text not null check (role in ('user', 'assistant')),
  content text not null,
  created_at timestamptz not null default now()
);

alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.invoices enable row level security;
alter table public.chat_messages enable row level security;

create policy "users read own orders"
  on public.orders
  for select
  using (auth.uid() = user_id);

create policy "users read own order items"
  on public.order_items
  for select
  using (
    exists (
      select 1 from public.orders o
      where o.id = order_items.order_id and o.user_id = auth.uid()
    )
  );

create policy "users read own invoices"
  on public.invoices
  for select
  using (auth.uid() = user_id);

create policy "users read own chat history"
  on public.chat_messages
  for select
  using (auth.uid() = user_id);
