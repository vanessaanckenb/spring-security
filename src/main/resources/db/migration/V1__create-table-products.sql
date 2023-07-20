create table products(

    id varchar(100) not null unique,
    name varchar(100) not null unique,
    price decimal not null,

    primary key(id)
);