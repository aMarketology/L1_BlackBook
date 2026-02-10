create table public.profiles (
  id uuid not null,
  username text not null,
  created_at timestamp with time zone null default now(),
  updated_at timestamp with time zone null default now(),
  constraint profiles_pkey primary key (id),
  constraint profiles_username_key unique (username),
  constraint profiles_id_fkey foreign KEY (id) references auth.users (id) on delete CASCADE,
  constraint profiles_username_check check ((username ~ '^[a-zA-Z0-9_]{3,20}$'::text))
) TABLESPACE pg_default;

create index IF not exists idx_profiles_username on public.profiles using btree (username) TABLESPACE pg_default;

create trigger set_timestamp_profiles BEFORE
update on profiles for EACH row
execute FUNCTION handle_updated_at ();