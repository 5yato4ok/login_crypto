create table if not exists users (
  id integer primary key autoincrement,
  uuid text UNIQUE NOT NULL,
  salt text UNIQUE NOT NULL,
  username text UNIQUE not null,
  fullname text not null,
  country text not null,
  email text not null,
  age integer not null,
  password text not null
);