from dataclasses import dataclass, fields
from enum import Enum
from typing import Type


@dataclass(frozen=True)
class DialectConfig:
    placeholder: str


class Dialect(Enum):
    POSTGRES = DialectConfig(placeholder="%s")


class SqlGenerator:
    dialect: Dialect
    table_name: str
    id_name: str
    column_list: str
    placeholder_list: str
    insert_sql: str
    select_all_sql: str
    select_by_id_sql: str
    delete_by_id_sql: str

    def __init__(
        self,
        table_name: str,
        datacls: Type,
        id_name: str = "id",
        dialect: Dialect = Dialect.POSTGRES,
    ) -> None:
        self.dialect = dialect
        self.table_name = table_name
        self.id_name = id_name
        datacls_fields = fields(datacls)
        self.column_list = ",".join([f.name for f in datacls_fields])
        self.placeholder_list = ",".join(
            [dialect.value.placeholder] * len(datacls_fields)
        )
        self.insert_sql = f"insert into {self.table_name} ({self.column_list}) values ({self.placeholder_list})"
        self.select_all_sql = f"select {self.column_list} from {self.table_name}"
        self.select_by_id_sql = f"{self.select_all_sql} where {self.id_name}={self.dialect.value.placeholder}"
        self.delete_by_id_sql = f"delete from {self.table_name} where {self.id_name}={self.dialect.value.placeholder}"

    def select_by_column(self, column_name: str) -> str:
        return f"{self.select_all_sql} where {column_name}={self.dialect.value.placeholder}"
