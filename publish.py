"""Збирання пакета даних для каналу роздачі ua_compliance.

Три кроки; секретні ключі з машини підписанта не виходять:

    python3 publish.py prepare parameters 20261101 --expires 2027-03-31 \\
        --min-app 0.1.0 --notes "Закон про Державний бюджет на 2027 рік" parameters.csv
    python3 publish.py sign build/parameters-20261101   # носії з ключами — по черзі
    python3 publish.py pack build/parameters-20261101

`sign` шукає секретний ключ на підключених носіях (`/Volumes/*/ua_key*.key`), підписує
ним маніфест (пароль питає сам minisign), одразу перевіряє підпис кодом застосунку й виймає
носій; просить наступний, доки не набереться поріг. Ключ з носія нікуди не копіюється.

`pack` перевіряє пакет **кодом самого застосунку** (розбір CSV, підписи, поріг ключів) з
копії репозиторію ua_compliance поруч (або з UA_COMPLIANCE_PATH) і лише тоді збирає zip.
Друкує команду публікації релізу.
"""

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import date

HERE = pathlib.Path(__file__).resolve().parent
APP = pathlib.Path(os.environ.get("UA_COMPLIANCE_PATH", HERE.parent / "ua_compliance"))
sys.path.insert(0, str(APP))

from ua_compliance.packages import keys as keys_module  # noqa: E402
from ua_compliance.packages import parse  # noqa: E402
from ua_compliance.packages.reader import PackageError  # noqa: E402
from ua_compliance.packages.signature import SignatureError, verify_detached  # noqa: E402

PARSERS = {"parameters": parse.parse_parameters, "classifiers": parse.parse_classifiers}
MANIFEST = "manifest.json"
# Підказки друкуємо тим інтерпретатором, яким запущено: у системному Python немає cryptography.
PYTHON = ".venv/bin/python" if pathlib.Path(sys.prefix).resolve() == (HERE / ".venv").resolve() else "python3"


def prepare(args):
	if args.channel not in PARSERS:
		raise SystemExit(f"Канал {args.channel} не підтримується; є: {', '.join(PARSERS)}")
	target = HERE / "build" / f"{args.channel}-{args.version}"
	if target.exists():
		raise SystemExit(f"{target} уже є: версія не перевидається, візьміть наступну")
	(target / "data").mkdir(parents=True)

	files = []
	for source in map(pathlib.Path, args.files):
		raw = source.read_bytes()
		name = f"data/{source.name}"
		try:
			PARSERS[args.channel](name, raw)
		except PackageError as error:
			shutil.rmtree(target)
			raise SystemExit(str(error)) from None
		(target / name).write_bytes(raw)
		files.append({"name": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})

	manifest = {
		"type": "ua-compliance-package",
		"channel": args.channel,
		"version": int(args.version),
		"created": date.today().isoformat(),
		"expires": args.expires,
		"min_app_version": args.min_app,
		"files": files,
		"notes": args.notes,
	}
	(target / MANIFEST).write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
	print(f"Маніфест: {target / MANIFEST}\nПідписати (носії з ключами — по черзі):")
	print(f"  {PYTHON} publish.py sign {target.relative_to(HERE)}")


def _key_number(key_id):
	"""Номер ключа (1…3) за ідентифікатором, який повертає verify_detached."""
	for number, encoded in enumerate(keys_module.trusted_keys(), 1):
		if base64.b64encode(base64.b64decode(encoded)[2:10]).decode() == key_id:
			return number


def _minisign_id(number):
	"""Ідентифікатор ключа так, як його друкує minisign: його й звіряють із носієм."""
	return base64.b64decode(keys_module.trusted_keys()[number - 1])[2:10][::-1].hex().upper()


def _signed(target, manifest_bytes):
	"""{номер ключа: файл підпису} для чинних підписів пакета."""
	signed = {}
	for path in sorted(target.glob(f"{MANIFEST}*.minisig")):
		try:
			signed[_key_number(verify_detached(manifest_bytes, path.read_text(), keys_module.trusted_keys()))] = path
		except SignatureError as error:
			print(f"  {path.name}: {error}")
	return signed


def _check_files(target, manifest):
	for item in manifest["files"]:
		raw = (target / item["name"]).read_bytes()
		if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
			raise SystemExit(f"Файл {item['name']} змінено після prepare")


def sign(args):
	target = pathlib.Path(args.dir).resolve()
	manifest_bytes = (target / MANIFEST).read_bytes()
	_check_files(target, json.loads(manifest_bytes))
	if not keys_module.trusted_keys():
		raise SystemExit(f"У {APP} ключі ще не закріплені: застосунок такий пакет не прийме")
	if not shutil.which("minisign"):
		raise SystemExit("Немає minisign: brew install minisign")

	tried = set()  # файли ключів, якими вже підписано в цьому запуску або які не підійшли
	while len(signed := _signed(target, manifest_bytes)) < keys_module.THRESHOLD:
		candidates = []
		for key in sorted(pathlib.Path(args.volumes).glob("*/ua_key*.key")):
			hint = re.search(r"(\d+)", key.stem)
			if key not in tried and not (hint and int(hint.group(1)) in signed):
				candidates.append(key)
		if not candidates:
			done = ", ".join(map(str, sorted(signed))) or "жодним"
			try:
				input(
					f"Підписано ключами: {done}; потрібно ще {keys_module.THRESHOLD - len(signed)}. "
					"Вставте носій з іншим ключем і натисніть Enter (Ctrl+C — вийти) "
				)
			except (EOFError, KeyboardInterrupt):
				raise SystemExit("\nПерервано; зроблені підписи збережено — запустіть sign ще раз") from None
			continue

		key = candidates[0]
		pending = target / "pending.sig.tmp"  # поза маскою підписів, доки не перевірено
		print(f"Ключ {key}")
		result = subprocess.run(["minisign", "-Sm", target / MANIFEST, "-s", key, "-x", pending])
		if result.returncode:
			pending.unlink(missing_ok=True)
			print("Не підписано (невірний пароль?) — ще раз")
			continue
		try:
			number = _key_number(verify_detached(manifest_bytes, pending.read_text(), keys_module.trusted_keys()))
		except SignatureError as error:
			pending.unlink()
			tried.add(key)
			print(f"{key}: {error} — цей ключ не годиться")
			continue
		tried.add(key)
		if number in signed:
			pending.unlink()
			print(f"Ключем {number} пакет уже підписано — потрібен інший")
		else:
			pending.rename(target / f"{MANIFEST}.key{number}.minisig")
			print(f"Підписано ключем {number} ({_minisign_id(number)})")
		if not args.keep_mounted and os.path.ismount(key.parent):  # папку на диску не виймаємо
			subprocess.run(["diskutil", "eject", key.parent], check=False)

	print(f"Підписів {len(signed)} з {keys_module.THRESHOLD}. Далі:\n  {PYTHON} publish.py pack {target.relative_to(HERE)}")


def pack(args):
	target = pathlib.Path(args.dir).resolve()
	manifest_bytes = (target / MANIFEST).read_bytes()
	manifest = json.loads(manifest_bytes)

	if not keys_module.trusted_keys():
		raise SystemExit(f"У {APP} ключі ще не закріплені: застосунок такий пакет не прийме")
	key_ids = _signed(target, manifest_bytes)
	if len(key_ids) < keys_module.THRESHOLD:
		raise SystemExit(f"Підписів {len(key_ids)}, потрібно {keys_module.THRESHOLD}")
	_check_files(target, manifest)

	name = f"ua-{manifest['channel']}-{manifest['version']}.zip"
	archive_path = HERE / "build" / name
	with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
		archive.write(target / MANIFEST, MANIFEST)
		for path in sorted(target.glob(f"{MANIFEST}*.minisig")):
			archive.write(path, path.name)
		for item in manifest["files"]:
			archive.write(target / item["name"], item["name"])
	tag = f"{manifest['channel']}-{manifest['version']}"
	print(f"Пакет: {archive_path} (підписів {len(key_ids)})\nОпублікувати:")
	print(f'  gh release create {tag} {archive_path} --title "{tag}" --notes "{manifest["notes"]}"')


def main():
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	commands = parser.add_subparsers(dest="command", required=True)
	p = commands.add_parser("prepare")
	p.add_argument("channel")
	p.add_argument("version")
	p.add_argument("--expires", required=True, help="РРРР-ММ-ДД; після неї пакет не застосовується")
	p.add_argument("--min-app", required=True, help="найнижча версія застосунку, яка прийме пакет")
	p.add_argument("--notes", required=True, help="що й чому змінюється — видно в передпоказі")
	p.add_argument("files", nargs="+")
	p.set_defaults(run=prepare)
	g = commands.add_parser("sign")
	g.add_argument("dir")
	g.add_argument("--volumes", default="/Volumes", help="де шукати носії з ua_key*.key (або папки з ними)")
	g.add_argument("--keep-mounted", action="store_true", help="не виймати носій після підпису")
	g.set_defaults(run=sign)
	k = commands.add_parser("pack")
	k.add_argument("dir")
	k.set_defaults(run=pack)
	args = parser.parse_args()
	args.run(args)


if __name__ == "__main__":
	main()
