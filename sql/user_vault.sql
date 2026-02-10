create table public.user_vault (
  id uuid not null,
  username text not null,
  wallet_address text not null,
  root_pubkey text not null,
  operational_pubkey text null,
  encrypted_shard_a_blob text null,
  encrypted_shard_b_blob text null,
  daily_spending_limit numeric null default 500.00,
  pin_hash text null,
  client_salt text not null,
  kdf_iterations integer null default 3,
  account_status text null default 'active'::text,
  created_at timestamp with time zone null default now(),
  updated_at timestamp with time zone null default now(),
  constraint user_vault_pkey primary key (id),
  constraint user_vault_username_key unique (username),
  constraint user_vault_wallet_address_key unique (wallet_address),
  constraint user_vault_id_fkey foreign KEY (id) references auth.users (id) on delete CASCADE
) TABLESPACE pg_default;

create index IF not exists idx_vault_wallet_address on public.user_vault using btree (wallet_address) TABLESPACE pg_default;

create index IF not exists idx_vault_username on public.user_vault using btree (username) TABLESPACE pg_default;