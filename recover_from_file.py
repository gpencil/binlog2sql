#!/usr/bin/env python3
"""
从本地 binlog 文件生成回滚 SQL（适用于阿里云 RDS 下载的 binlog 文件）

支持：
  DELETE → 生成 INSERT（恢复被删除的行）
  UPDATE → 生成反向 UPDATE（把数据改回原来的值）

用法：
  python3 recover_from_file.py <binlog文件> [选项]

示例：
  # 恢复所有 DELETE
  python3 recover_from_file.py mysql-bin.000490.log

  # 只恢复某张表的 DELETE
  python3 recover_from_file.py mysql-bin.000490.log -t user_voices

  # 恢复 UPDATE（把数据改回去）
  python3 recover_from_file.py mysql-bin.000490.log --type UPDATE

  # 指定时间范围
  python3 recover_from_file.py mysql-bin.000490.log --start "2026-05-09 10:00:00" --stop "2026-05-09 11:00:00"

  # 输出到文件
  python3 recover_from_file.py mysql-bin.000490.log > recover.sql
"""

import struct
import datetime
import argparse
import sys

# ── event type constants ──────────────────────────────────────────────────────
TABLE_MAP_EVENT    = 19
DELETE_ROWS_EVENT_V1 = 25
UPDATE_ROWS_EVENT_V1 = 24
WRITE_ROWS_EVENT_V1  = 23
DELETE_ROWS_EVENT  = 32
UPDATE_ROWS_EVENT  = 31
WRITE_ROWS_EVENT   = 30

# ── column type constants ─────────────────────────────────────────────────────
MYSQL_TYPE_TINY       = 1
MYSQL_TYPE_SHORT      = 2
MYSQL_TYPE_LONG       = 3
MYSQL_TYPE_FLOAT      = 4
MYSQL_TYPE_DOUBLE     = 5
MYSQL_TYPE_LONGLONG   = 8
MYSQL_TYPE_INT24      = 9
MYSQL_TYPE_DATE       = 10
MYSQL_TYPE_DATETIME   = 12
MYSQL_TYPE_TIMESTAMP  = 7
MYSQL_TYPE_YEAR       = 13
MYSQL_TYPE_VARCHAR    = 15
MYSQL_TYPE_VAR_STRING = 253
MYSQL_TYPE_STRING     = 254
MYSQL_TYPE_BLOB       = 252
MYSQL_TYPE_MEDIUM_BLOB = 250
MYSQL_TYPE_LONG_BLOB  = 251
MYSQL_TYPE_TINY_BLOB  = 249
MYSQL_TYPE_NEWDECIMAL = 246


def read_lenc(data, pos):
    b = data[pos]
    if b < 0xfb:   return b, pos + 1
    elif b == 0xfc: return struct.unpack_from('<H', data, pos+1)[0], pos + 3
    elif b == 0xfd: return struct.unpack_from('<I', data[pos+1:pos+4] + b'\x00')[0], pos + 4
    else:           return struct.unpack_from('<Q', data, pos+1)[0], pos + 9


def parse_table_map(data, pos):
    table_id = struct.unpack_from('<Q', data[pos:pos+6] + b'\x00\x00')[0]; pos += 6
    pos += 2  # flags
    schema_len = data[pos]; pos += 1
    schema = data[pos:pos+schema_len].decode(); pos += schema_len; pos += 1
    table_len = data[pos]; pos += 1
    table = data[pos:pos+table_len].decode(); pos += table_len; pos += 1
    col_count, pos = read_lenc(data, pos)
    col_types = list(data[pos:pos+col_count]); pos += col_count
    meta_len, pos = read_lenc(data, pos)
    metadata = list(data[pos:pos+meta_len])
    return table_id, schema, table, col_types, metadata


def parse_value(data, pos, col_type, metadata, meta_idx):
    """解析单个列的值，返回 (value, new_pos, new_meta_idx)"""
    if col_type == MYSQL_TYPE_TINY:
        return data[pos], pos+1, meta_idx

    elif col_type == MYSQL_TYPE_SHORT:
        return struct.unpack_from('<H', data, pos)[0], pos+2, meta_idx

    elif col_type in (MYSQL_TYPE_LONG, MYSQL_TYPE_INT24):
        return struct.unpack_from('<I', data, pos)[0], pos+4, meta_idx

    elif col_type == MYSQL_TYPE_LONGLONG:
        return struct.unpack_from('<Q', data, pos)[0], pos+8, meta_idx

    elif col_type == MYSQL_TYPE_FLOAT:
        return struct.unpack_from('<f', data, pos)[0], pos+4, meta_idx

    elif col_type == MYSQL_TYPE_DOUBLE:
        return struct.unpack_from('<d', data, pos)[0], pos+8, meta_idx

    elif col_type in (MYSQL_TYPE_VARCHAR, MYSQL_TYPE_VAR_STRING):
        max_len = (metadata[meta_idx] | (metadata[meta_idx+1] << 8)) if meta_idx+1 < len(metadata) else 255
        if max_len > 255:
            length = struct.unpack_from('<H', data, pos)[0]; pos += 2
        else:
            length = data[pos]; pos += 1
        return data[pos:pos+length].decode('utf8', 'replace'), pos+length, meta_idx+2

    elif col_type in (MYSQL_TYPE_BLOB, MYSQL_TYPE_MEDIUM_BLOB, MYSQL_TYPE_LONG_BLOB, MYSQL_TYPE_TINY_BLOB):
        blob_len_bytes = metadata[meta_idx] if meta_idx < len(metadata) else 2
        if   blob_len_bytes == 1: length = data[pos]; pos += 1
        elif blob_len_bytes == 2: length = struct.unpack_from('<H', data, pos)[0]; pos += 2
        elif blob_len_bytes == 3: length = struct.unpack_from('<I', data[pos:pos+3]+b'\x00')[0]; pos += 3
        else:                     length = struct.unpack_from('<I', data, pos)[0]; pos += 4
        return data[pos:pos+length], pos+length, meta_idx+1

    elif col_type == MYSQL_TYPE_STRING:
        length = data[pos]; pos += 1
        return data[pos:pos+length].decode('utf8', 'replace'), pos+length, meta_idx

    elif col_type == MYSQL_TYPE_DATETIME:
        val = struct.unpack_from('<Q', data, pos)[0]; pos += 8
        d = val // 1000000; t = val % 1000000
        return (f"{d//10000:04d}-{(d//100)%100:02d}-{d%100:02d} "
                f"{t//10000:02d}:{(t//100)%100:02d}:{t%100:02d}"), pos, meta_idx

    elif col_type == MYSQL_TYPE_TIMESTAMP:
        val = struct.unpack_from('<I', data, pos)[0]; pos += 4
        return datetime.datetime.fromtimestamp(val).strftime('%Y-%m-%d %H:%M:%S'), pos, meta_idx

    elif col_type == MYSQL_TYPE_DATE:
        val = struct.unpack_from('<I', data[pos:pos+3]+b'\x00')[0]; pos += 3
        return f"{val>>9:04d}-{(val>>5)&0xf:02d}-{val&0x1f:02d}", pos, meta_idx

    elif col_type == MYSQL_TYPE_YEAR:
        val = data[pos]; pos += 1
        return (1900 + val if val else 0), pos, meta_idx

    elif col_type == MYSQL_TYPE_NEWDECIMAL:
        prec  = metadata[meta_idx]   if meta_idx   < len(metadata) else 10
        scale = metadata[meta_idx+1] if meta_idx+1 < len(metadata) else 0
        dig2bytes = [0, 1, 1, 2, 2, 3, 3, 4, 4, 4]
        intg = prec - scale
        intg0, intg_x = divmod(intg, 9)
        frac0, frac_x = divmod(scale, 9)
        size = intg0*4 + dig2bytes[intg_x] + frac0*4 + dig2bytes[frac_x]
        return data[pos:pos+size].hex(), pos+size, meta_idx+2

    else:
        return f'[type:{col_type}]', pos, meta_idx


def parse_row(data, pos, col_types, metadata, event_end):
    """解析一行数据，返回 (values_list, new_pos)"""
    null_bytes = (len(col_types) + 7) // 8
    null_bitmap = data[pos:pos+null_bytes]; pos += null_bytes
    row = []
    meta_idx = 0
    for i, ct in enumerate(col_types):
        is_null = (null_bitmap[i // 8] >> (i % 8)) & 1
        if is_null:
            row.append(None)
            continue
        try:
            val, pos, meta_idx = parse_value(data, pos, ct, metadata, meta_idx)
            row.append(val)
        except Exception as e:
            row.append(f'[ERR:{e}]')
            break
    return row, pos


def fmt(val):
    """把 Python 值格式化成 SQL 字面量"""
    if val is None:
        return 'NULL'
    if isinstance(val, str):
        return "'" + val.replace("\\", "\\\\").replace("'", "\\'") + "'"
    if isinstance(val, bytes):
        try:
            return "'" + val.decode('utf8').replace("\\", "\\\\").replace("'", "\\'") + "'"
        except Exception:
            return "0x" + val.hex()
    if isinstance(val, float):
        return repr(val)
    return str(val)


def parse_binlog(filepath, only_tables=None, only_schemas=None,
                 start_time=None, stop_time=None, event_types=None):
    """
    解析本地 binlog 文件，生成回滚 SQL。

    DELETE → INSERT（恢复删除的行）
    UPDATE → 反向 UPDATE（还原到修改前的值）

    返回 list of sql strings
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    table_maps = {}  # table_id → {schema, table, col_types, metadata}
    results = []

    pos = 4  # 跳过 magic header
    while pos < len(data) - 19:
        try:
            ts         = struct.unpack_from('<I', data, pos)[0]
            event_type = data[pos + 4]
            event_len  = struct.unpack_from('<I', data, pos + 9)[0]
            if event_len == 0:
                break
            event_data = pos + 19
            event_end  = pos + event_len
            event_time = datetime.datetime.fromtimestamp(ts)

            if event_type == TABLE_MAP_EVENT:
                tid, schema, table, col_types, metadata = parse_table_map(data, event_data)
                table_maps[tid] = {
                    'schema': schema, 'table': table,
                    'col_types': col_types, 'metadata': metadata,
                }

            elif event_type in (DELETE_ROWS_EVENT, DELETE_ROWS_EVENT_V1,
                                UPDATE_ROWS_EVENT, UPDATE_ROWS_EVENT_V1):

                # 时间过滤
                if start_time and event_time < start_time: pos = event_end; continue
                if stop_time  and event_time > stop_time:  pos = event_end; continue

                table_id = struct.unpack_from('<Q', data[event_data:event_data+6] + b'\x00\x00')[0]
                if table_id not in table_maps:
                    pos = event_end; continue

                tm        = table_maps[table_id]
                schema    = tm['schema']
                table     = tm['table']
                col_types = tm['col_types']
                metadata  = tm['metadata']

                # 表过滤
                if only_schemas and schema not in only_schemas: pos = event_end; continue
                if only_tables  and table  not in only_tables:  pos = event_end; continue

                is_delete = event_type in (DELETE_ROWS_EVENT, DELETE_ROWS_EVENT_V1)
                is_update = event_type in (UPDATE_ROWS_EVENT, UPDATE_ROWS_EVENT_V1)

                # 类型过滤
                if event_types:
                    if is_delete and 'DELETE' not in event_types: pos = event_end; continue
                    if is_update and 'UPDATE' not in event_types: pos = event_end; continue

                p = event_data + 6 + 2  # 跳过 table_id + flags
                # v2 事件有 extra_data_len 字段
                if event_type in (DELETE_ROWS_EVENT, UPDATE_ROWS_EVENT, WRITE_ROWS_EVENT):
                    extra_len = struct.unpack_from('<H', data, p)[0]; p += extra_len

                col_count, p = read_lenc(data, p)
                bitmap_bytes = (col_count + 7) // 8
                p += bitmap_bytes  # present bitmap（DELETE/INSERT 只有一个，UPDATE 有两个）
                if is_update:
                    p += bitmap_bytes  # UPDATE 的 after-image bitmap

                while p < event_end - 4:
                    if is_delete:
                        before, p = parse_row(data, p, col_types, metadata, event_end)
                        vals = ', '.join(fmt(v) for v in before)
                        sql = (f"-- {event_time}  DELETE→INSERT\n"
                               f"INSERT INTO `{schema}`.`{table}` VALUES ({vals});")
                        results.append(sql)

                    elif is_update:
                        before, p = parse_row(data, p, col_types, metadata, event_end)
                        after,  p = parse_row(data, p, col_types, metadata, event_end)
                        # 生成反向 UPDATE：把 after 改回 before，WHERE 用 after 定位
                        set_clause   = ', '.join(f'col_{i}={fmt(v)}' for i, v in enumerate(before))
                        where_clause = ' AND '.join(f'col_{i}={fmt(v)}' for i, v in enumerate(after))
                        sql = (f"-- {event_time}  UPDATE rollback\n"
                               f"-- before: {[fmt(v) for v in before]}\n"
                               f"-- after:  {[fmt(v) for v in after]}\n"
                               f"UPDATE `{schema}`.`{table}` SET {set_clause} WHERE {where_clause} LIMIT 1;")
                        results.append(sql)

            pos = event_end
        except Exception:
            break

    return results


def main():
    parser = argparse.ArgumentParser(
        description='从本地 binlog 文件生成回滚 SQL（支持 DELETE 和 UPDATE）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('binlog_file', help='本地 binlog 文件路径')
    parser.add_argument('-t', '--table', help='只处理指定表名（多个用逗号分隔）')
    parser.add_argument('-d', '--database', help='只处理指定库名')
    parser.add_argument('--type', dest='sql_type', default='DELETE',
                        help='要恢复的操作类型：DELETE / UPDATE / DELETE,UPDATE（默认 DELETE）')
    parser.add_argument('--start', dest='start_time', help='开始时间 "YYYY-MM-DD HH:MM:SS"')
    parser.add_argument('--stop',  dest='stop_time',  help='结束时间 "YYYY-MM-DD HH:MM:SS"')
    args = parser.parse_args()

    only_tables  = [t.strip() for t in args.table.split(',')] if args.table else None
    only_schemas = [args.database] if args.database else None
    event_types  = [t.strip().upper() for t in args.sql_type.split(',')]
    start_time   = datetime.datetime.strptime(args.start_time, '%Y-%m-%d %H:%M:%S') if args.start_time else None
    stop_time    = datetime.datetime.strptime(args.stop_time,  '%Y-%m-%d %H:%M:%S') if args.stop_time  else None

    sqls = parse_binlog(
        filepath=args.binlog_file,
        only_tables=only_tables,
        only_schemas=only_schemas,
        start_time=start_time,
        stop_time=stop_time,
        event_types=event_types,
    )

    if not sqls:
        print('-- 未找到匹配的事件', file=sys.stderr)
        sys.exit(1)

    print(f'-- 共找到 {len(sqls)} 条回滚语句', file=sys.stderr)
    print('SET NAMES utf8mb4;')
    print()
    for sql in sqls:
        print(sql)
        print()


if __name__ == '__main__':
    main()
