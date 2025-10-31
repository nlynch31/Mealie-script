#!/usr/bin/env python3
"""
Bulk-parse every *un-parsed* recipe in Mealie ≥ v2.8
"""

import re, argparse, json, os, pathlib, sys, time, requests, pprint
from tqdm import tqdm
from requests.exceptions import HTTPError

# ── CONFIG ───────────────────────────────────────────────────────────────
BASE  = os.getenv("MEALIE_BASE_URL", "$YOUR MEALIE URL HERE")
TOKEN = os.getenv("MEALIE_API_TOKEN", "$YOUR API TOKEN HERE")
HEAD  = {"Authorization": TOKEN, "Accept": "application/json"}

PAGE  = 200
CONF  = 0.80          # confidence **fraction** (0.80 = 80 %)
DELAY = 0.1           # polite pause between recipes

OUT   = pathlib.Path("review_low_confidence.json")
PARSE_ORDER = ["nlp", "openai"]
# ─────────────────────────────────────────────────────────────────────────

class AlreadyParsed(Exception):
    pass

import re     # <- needed for the regex in rule #3

# ---------------- misc helpers ------------------------------------------
def slim(obj: dict | None) -> dict | None:
    """
    Return just {"id": <uuid>, "name": <string>} for food/unit objects,
    or None if the object is missing / has no id.
    """
    if obj and isinstance(obj, dict) and obj.get("id"):
        return {"id": obj["id"], "name": obj.get("name", "")}
    return None


SERVING_PHRASES = {"for serving", "for garnish", "for dipping"}

def ensure_food_object(food: dict | None) -> dict | None:
    """
    If `food` is a dict missing an id but has a name, POST it to /foods.
    If the POST fails or name is blank, return None.
    """
    # nothing to do if there's already an id, or no dict at all
    if not food or food.get("id"):
        return food

    name = (food.get("name") or "").strip()
    if not name:
        # no meaningful name to register
        return None

    try:
        r = requests.post(
            f"{BASE}/foods",
            headers=HEAD,
            json={"name": name},
            timeout=30,
        )
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"⚠️  Couldn’t create food “{name}”: {e}")
        return None

    data = r.json()
    return {"id": data["id"], "name": data["name"]}


def looks_suspicious(ing: dict) -> bool:
    """
    Much lighter filter:
      • ignore obvious serving suggestions
      • error only if quantity == 0 **and** unit is not None
    """
    note = (ing.get("note") or "").lower()

    # ignore lines like “chips … for dipping”
    if any(p in note for p in SERVING_PHRASES):
        return False

    # zero qty but still has a unit → probably mis-parsed
    if ing.get("quantity", 0) == 0 and ing.get("unit") is not None:
        return True

    return False            # everything else is acceptable

def extract_raw_lines(recipe_json):
    """
    Return list[str] of ingredient lines ready for the parser.

    • If recipeIngredient is already a list[str] → return
    • If every dict in recipeIngredient has food == null → legacy  → extract
    • Else at least one food ≠ null → already parsed → raise AlreadyParsed
    • Legacy “ingredients[]” from v1 imports → extract rawText
    """
    if "recipeIngredient" in recipe_json:
        items = recipe_json["recipeIngredient"]
        if not items:
            raise KeyError("Empty recipeIngredient list")

        first = items[0]

        # modern/plain-string schema
        if isinstance(first, str):
            return items

        # dicts – decide legacy vs parsed
        if isinstance(first, dict):
            all_food_null = all(it.get("food") is None for it in items)
            if not all_food_null:
                raise AlreadyParsed

            # legacy → grab best guess of original text
            return [
                (it.get("originalText")
                 or it.get("rawText")
                 or it.get("note")  # ← many NYT imports put the line here
                 or re.sub(r"^\s*\d+[¼½¾⅓⅔⅛⅜⅝⅞/ \t--]*", "",  # strip qty/unit
                           it.get("display", "")))
                .strip()
                for it in items
            ]

    if "ingredients" in recipe_json:
        return [it["rawText"] for it in recipe_json["ingredients"]]

    raise KeyError("No ingredient field found")


def parse_lines(lines: list[str], parser: str = "nlp") -> list[dict] | None:
    """
    Return parser output or None if the request errors out.
    """
    payload = {"strategy": parser, "ingredients": lines}
    try:
        r = requests.post(
            f"{BASE}/parser/ingredients",
            headers=HEAD,
            json=payload,
            timeout=30,
        )
        r.raise_for_status()
        return r.json()
    except HTTPError as e:
        print(f"⚠️  Parser `{parser}` failed: {e}")
        return None

def good_enough(block):
    """
    True only if EVERY line:
      • confidence ≥ CONF
      • food is not null
      • (quantity > 0)  OR  unit is None
    """
    return all(
        (ln["confidence"]["average"] >= CONF)
        and (
            ln["ingredient"]["quantity"] > 0
            or ln["ingredient"]["unit"] is None
        )
        for ln in block
    )

def parse_with_fallback(lines: list[str]) -> tuple[list[dict], str | None]:
    """
    Try each parser in PARSE_ORDER.  On any HTTP error, low confidence,
    or suspicious parse, move on.  Return the first clean block + its name,
    or ([], None) if none succeeded.
    """
    for strategy in PARSE_ORDER:
        block = parse_lines(lines, parser=strategy)
        if block is None:
            # HTTP error or network hiccup — try next strategy
            continue

        # numeric threshold check
        if not all(item["confidence"]["average"] >= CONF for item in block):
            continue

        # lightweight “suspicious” check
        if any(looks_suspicious(item["ingredient"]) for item in block):
            continue

        # passed all tests — slim and return
        for p in block:
            ingr = p["ingredient"]
            ingr["food"] = slim(ingr.get("food"))
            ingr["unit"] = slim(ingr.get("unit"))
        return block, strategy

    # no parser satisfied our criteria
    return [], None


def get_all_slugs():
    slugs, page = [], 1
    while True:
        r = requests.get(f"{BASE}/recipes",
                         params={"page": page, "perPage": PAGE},
                         headers=HEAD, timeout=30)
        r.raise_for_status()
        data = r.json()
        slugs.extend([it["slug"] for it in data["items"]
                      if not it.get("hasParsedIngredients")])
        if page >= data["total_pages"]:
            break
        page += 1
    return slugs


# ── FIX ① : PATCH just the list -----------------------------------------
def patch_recipe(slug: str, ingredient_list: list[dict]):
    payload = {"recipeIngredient": ingredient_list}

    pathlib.Path("last_payload.json").write_text(json.dumps(payload, indent=2))
    print("🔎  PATCH payload written to last_payload.json")

    r = requests.patch(f"{BASE}/recipes/{slug}",
                       headers=HEAD, json=payload, timeout=30)
    if r.status_code >= 400:
        print("\n--- SERVER RESPONSE ---")
        try:
            pprint.pp(r.json())
        except ValueError:
            print(r.text)
        print("-----------------------\n")
    r.raise_for_status()
# ------------------------------------------------------------------------


def main(conf_thresh: int, max_recipes: int | None, after_slug: str | None = None):
    to_review, parsed_ok = [], []
    slugs = get_all_slugs()

    # ── NEW: skip everything through --after-slug ─────────────
    if after_slug:
        try:
            idx = slugs.index(after_slug)
            slugs = slugs[idx+1:]
            print(f"⏭️  Resuming after “{after_slug}” (skipped {idx+1} recipes)")
        except ValueError:
            print(f"⚠️  --after-slug '{after_slug}' not found; parsing from top")
    # ───────────────────────────────────────────────────────────


    if max_recipes:
        slugs = slugs[:max_recipes]
        print(f"Trial mode → {len(slugs)} recipes of {len(get_all_slugs())}")

    if not slugs:
        print("Nothing left to parse.")
        return

    for slug in tqdm(slugs, desc="Parsing"):
        raw = requests.get(f"{BASE}/recipes/{slug}", headers=HEAD, timeout=30).json()
        if not raw.get("recipeIngredient"):      # empty list or None
            continue
    #
        try:
            raw_lines = extract_raw_lines(raw)
        except AlreadyParsed:
            continue

        parsed, which = parse_with_fallback(raw_lines)
        
        if which == "openai":
            print(f"\n🌐  Using OpenAI parser for {slug}")


        if which is None:     # still below threshold
            to_review.append({"slug": slug, "name": raw["name"], "low_confidence": parsed})
            continue

        # ---- SUCCESS branch -------------------------------------------------
        new_list = []
        suspicious = False

        for line in parsed:                              # each parsed line
            ingr = line["ingredient"].copy()             # inner dict

            # 1) ensure the food exists in Mealie; create if needed
            ingr["food"] = ensure_food_object(ingr.get("food"))

            # 2) keep only {id, name} for food / unit
            ingr["food"] = slim(ingr.get("food"))
            ingr["unit"] = slim(ingr.get("unit"))

            # 3) quick sanity flags
            if (
                (ingr["food"] is None and not ingr.get("note"))      # no food & no note
                or (ingr.get("quantity", 0) == 0 and ingr["unit"] is not None)  # 0 qty but has unit
            ):
                suspicious = True

            # 4) drop parser-only keys
            ingr.pop("confidence", None)
            ingr.pop("display",    None)

            new_list.append(ingr)


        if suspicious:
            to_review.append({
                "slug": slug,
                "name": raw["name"],
                "low_confidence": new_list,
                "parser": which
            })
            continue            # don’t PATCH, go to next recipe

        patch_recipe(slug, new_list)
        parsed_ok.append(raw["name"])
        time.sleep(DELAY)

        # -----------------------------------------------------------------

    if parsed_ok:
        pathlib.Path("parsed_success.log").write_text("\n".join(parsed_ok))
        print(f"\n✅ Parsed {len(parsed_ok)} recipes → parsed_success.log")

    if to_review:
        OUT.write_text(json.dumps(to_review, indent=2))
        print(f"\n⚠  {len(to_review)} recipes need review → {OUT}")
    else:
        print(f"\n🎉 All done – every recipe ≥ {conf_thresh:.0%} confidence.")


# ── CLI ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Bulk-parse Mealie recipes safely")
    ap.add_argument("--conf", type=float, default=CONF,
                    help="minimum confidence fraction 0-1 (default 0.80)")
    ap.add_argument("--max", type=int, metavar="N",
                    help="parse at most N recipes (trial run)")
    ap.add_argument("--after-slug", metavar="SLUG",
                    help="skip all recipes up through this slug (then resume)")
    args = ap.parse_args()

    if not 0 < args.conf <= 1:
        sys.exit("Confidence must be 0–1 (e.g., 0.8 for 80 %).")

    main(conf_thresh=args.conf,
         max_recipes=args.max,
         after_slug=args.after_slug)
