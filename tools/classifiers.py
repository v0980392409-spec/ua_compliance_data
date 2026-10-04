"""Перетворення офіційних файлів класифікаторів у CSV каналу «класифікатори».

    python3 tools/classifiers.py katottg kodifikator.xlsx --valid-from 2020-11-26 > katottg.csv
    python3 tools/classifiers.py kved kved.json --valid-from 2012-01-01 > kved.csv

Схема CSV — контракт пакета: classifier, code, entry_name, parent_code, level,
valid_from, valid_to. Назви — дослівно з першоджерела. Перед видачею перевіряється, що
коди унікальні, а кожен батьківський код є в тому самому файлі: битий файл не має
дістатися до підпису.
"""

import argparse
import csv
import json
import sys

COLUMNS = ["classifier", "code", "entry_name", "parent_code", "level", "valid_from", "valid_to"]


# Категорія об'єкта — латинська літера в колонці «Категорія об'єкта» (Список скорочень
# до Кодифікатора, ред. наказу № 48 від 19.01.2024). Сам список задає лише значення
# літер, тож форми — загальновживані українські: перед назвою населеного пункту,
# після прикметникової назви. Слово з кодифікатора не змінюється. Без категорії
# «Київ» (місто) і «Київ» (село) при виборі не розрізнити — рішення власника 04.10.2026.
KATOTTG_FORMS = {
	"O": "{name} обл.",  # Автономна Республіка Крим, область
	"K": "м. {name}",  # місто зі спеціальним статусом
	"P": "{name} р-н",  # район в АР Крим, області
	"H": "{name} тер. громада",  # територіальна громада (прикметникова частина назви)
	"M": "м. {name}",
	"X": "с-ще {name}",
	"C": "с. {name}",
	"B": "{name} р-н",  # район у місті
}


def katottg_name(category, name):
	if category == "O" and name.startswith("Автономна Республіка"):
		return name
	form = KATOTTG_FORMS.get(category)
	if not form:
		raise SystemExit(f"Невідома категорія об'єкта «{category}» для «{name}» — список скорочень змінився")
	return form.format(name=name)


def katottg(path):
	"""Кодифікатор: рівні 1–4 і додатковий; код запису — найглибший заповнений рівень."""
	import openpyxl

	sheet = openpyxl.load_workbook(path, read_only=True).worksheets[0]
	rows = []
	header_seen = False
	for values in sheet.iter_rows(values_only=True):
		if not header_seen:
			header_seen = values[0] == "Перший рівень"
			continue
		levels = [str(v).strip() for v in values[:5] if v not in (None, "")]
		name = (values[6] or "").strip() if len(values) > 6 else ""
		if not levels or not name:
			continue
		rows.append(
			{
				"classifier": "КАТОТТГ",
				"code": levels[-1],
				"entry_name": katottg_name((values[5] or "").strip(), name),
				"parent_code": levels[-2] if len(levels) > 1 else "",
				"level": len(levels),
			}
		)
	if not header_seen:
		raise SystemExit("У файлі не знайдено заголовка «Перший рівень» — формат змінився")
	return rows


KVED_LEVELS = ("Код секції", "Код розділу", "Код групи", "Код класу")


def kved(path):
	"""КВЕД ДК 009:2010: секція → розділ → група → клас."""
	rows = []
	for item in json.load(open(path, encoding="utf-8")):
		# У файлі Держстату в назвах полів трапляється «\n» — нормалізуємо ключі.
		item = {key.strip(): (value or "").strip() for key, value in item.items()}
		codes = [item[key] for key in KVED_LEVELS if item.get(key)]
		rows.append(
			{
				"classifier": "КВЕД",
				"code": codes[-1],
				"entry_name": item["Назва"],
				"parent_code": codes[-2] if len(codes) > 1 else "",
				"level": len(codes),
			}
		)
	return rows


def check(rows):
	codes = [row["code"] for row in rows]
	duplicates = {code for code in codes if codes.count(code) > 1} if len(codes) < 2000 else _duplicates(codes)
	if duplicates:
		raise SystemExit(f"Повторені коди: {', '.join(sorted(duplicates)[:10])}")
	known = set(codes)
	orphans = [row["code"] for row in rows if row["parent_code"] and row["parent_code"] not in known]
	if orphans:
		raise SystemExit(f"Коди без батьківського запису: {', '.join(orphans[:10])}")


def _duplicates(codes):
	seen, repeated = set(), set()
	for code in codes:
		(repeated if code in seen else seen).add(code)
	return repeated


def main():
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("kind", choices=["katottg", "kved"])
	parser.add_argument("path")
	parser.add_argument("--valid-from", required=True, help="РРРР-ММ-ДД: з якої дати коди чинні")
	args = parser.parse_args()
	rows = katottg(args.path) if args.kind == "katottg" else kved(args.path)
	check(rows)
	writer = csv.DictWriter(sys.stdout, fieldnames=COLUMNS, lineterminator="\n")
	writer.writeheader()
	for row in rows:
		writer.writerow({**row, "valid_from": args.valid_from, "valid_to": ""})
	print(f"{args.kind}: {len(rows)} кодів", file=sys.stderr)


if __name__ == "__main__":
	main()
