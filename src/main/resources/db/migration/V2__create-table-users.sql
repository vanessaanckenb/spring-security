create table users(

    id varchar(100) not null unique,
    login varchar(100) not null unique,
    password varchar(100) not null,
    role varchar(20) not null,

    primary key(id)
);
