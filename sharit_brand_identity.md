# SHARIT — Brand Identity Reference

*Working document. Consolidates the brand direction, color system, and typography decided so far. Living reference — update as decisions evolve.*

---

## 1. What SHARIT is

SHARIT makes it easy to share valuable assets with people you already trust. Starting point: shared cars — tracking who used the car, how much they drove, and how costs should be divided. Not fundamentally a car product — a product for making shared ownership and shared use effortless, starting with cars and built to extend to other shared assets over time.

**Core values:** Trust · Fairness · Transparency · Effortlessness · Togetherness · Simplicity

**The core tension the brand identity has to hold:** warmth × precision. This is not a compromise between the two — the brand should feel structured and dependable (it deals with money and usage) *and* warm and personal (it exists between people who already know each other), simultaneously, not as a blend that dilutes both.

---

## 2. The feeling

Not "friendly." Not "trustworthy." Those are strategy words, not felt experience.

**What it should feel like:** the feeling of being handed the keys — the two-second moment of transfer, not the drive itself. The warmth of someone trusting you with something that matters to them, plus the quiet competence of knowing exactly what happens next because the system already worked it out.

**Relief, not excitement.** SHARIT doesn't want to pump anyone up. It wants someone to exhale. The feeling of checking the app and the number is already right — no math on a napkin, no argument required. Trust here is the absence of a task you expected to have to do yourself.

**What it should explicitly NOT feel like:**
- A banking app (too sterile)
- A rideshare app (too transactional, stranger-facing)
- A family group chat (too chaotic, unstructured)
- A productivity tool (too effortful)

If it feels like "using software," it's failed. It should feel more like a well-run household than a well-run company.

---

## 3. The world — "Threshold"

**Anchor concept:** the threshold. Not a place — a *moment*. The instant something crosses from "mine" to "ours" and back again. A shared car crosses from one person's hands to another's, every day, seamlessly, and the system quietly tracks the crossing so no one has to.

**Visual world:** first and last light. Early morning before anyone else is awake, warm low sun, long shadows — or the very end of dusk, when color hasn't fully drained from the sky. Not midday: midday has no threshold, nothing changing. Golden hour and blue hour — literally the two moments named for their light *changing*.

Reference scene: a kitchen counter at 6:40am, keys in a small dish, low orange light through a window, someone's coffee going cold because they're already halfway out the door. Domestic, quiet, slightly cinematic, never staged.

**One-sentence distillation:** *SHARIT lives in the last good light of the day, in the moment one thing is quietly becoming another.*

---

## 4. Visual direction

**Chosen direction: Painterly / mesh-gradient.** Soft, blurred, blended color — warm meeting cool within the same shape, no hard edges. This is the literal visual expression of the threshold concept: color changing without a visible seam.

### Explicitly rejected directions (and why)
- **Glassmorphism / literal glass rendering** — tested and dropped. Conceptually appealing ("transparency = trust") but in practice: (1) converges with current iOS visual language, risking a generic/derivative read rather than a distinctive one; (2) blur and low contrast collide directly with SHARIT's functional need to show numbers and cost breakdowns clearly. Glass is not banned outright from the brand universe but should be treated as fully retired from this direction, not a lingering option.
- **Illustrated human figures (people, characters, scenes with faces)** — dropped in favor of the mesh-gradient object illustration style (see §6). Reason: literal human illustration doesn't generalize cleanly as SHARIT extends beyond cars to other shared assets, and it pulled the system toward a different, less coherent visual language than the gradient-based identity.
- **Flat Swiss/grid poster graphics as the primary identity** — useful as a *structural discipline* (alignment, hierarchy, layout logic) but not as the visual identity itself. Precision is expressed through layout rigor, not through flat geometric graphic style.

### Color-temperature discipline
Every hero graphic should contain both a warm and cool note within the same gradient, blending with no hard edge — this is the non-negotiable visual signature of the direction. Warm alone reads cozy but sloppy; cool alone reads precise but cold. Both together, blended, is the brand.

---

## 5. Vocabulary

### Texture & material
**Use:** frosted (as in breath on cold glass, not literal glass), soft-focus, bloom, diffusion, haze, gauze, membrane, atmosphere, glow, bleed (color bleeding into color), wash, light film grain.

**Avoid:** chrome, steel, polish, gloss, mirror, plastic, lacquer (too hard-materiality). Also avoid craft/tactile words — ceramic, woven, hand-thrown, clay (belongs to the rejected illustrated-human/craft direction, not this one).

### Lighting
**Use:** ambient, low sun, backlit, glow-through, spill, halo, warm-cool contrast.

**Avoid:** spotlight, studio light, harsh shadow, high-contrast noir lighting — nothing should look "lit for a photoshoot." It should look like it was already, quietly, lit that way.

### Brand-copy words to avoid entirely
Seamless, smart, powered, ecosystem, platform, community (too vague — "the people you already trust" is specific, "community" is not), effortless (say what specifically is effortless instead of naming the word).

---

## 6. Illustration style

Reference technique (from brand references): a precise, thin black line-art drawing (e.g. a cocktail stirrer, simple object outline) sitting *on top of* soft, blurred color fields glowing through a translucent shape beneath it. Two techniques layered — sharp line + soft color-behind-glow — not one blurry style alone.

**Rule to protect:** this combination is the distinctive asset. Lock down before more than one contributor produces it:
- Line weight and color for the linework (fixed, thin, consistent)
- Number of blur/color blobs per illustration (keep restrained — 2–4 typical)
- Whether a translucent "container" shape is always present or optional
- Corner radius logic if a container shape is used
- A fixed, limited palette per illustration so "warm" doesn't drift into "whatever gradient looked good today"

**Open risk to test before fully committing:** the reference illustrations are simple, round, forgiving subjects (glasses, flowers, olives). SHARIT's actual subject matter (a car, a house key, a bike) has harder proportions people recognize instantly if wrong. Test the technique against an actual car illustration before scaling it across the product.

**Icon system:** the full illustration technique is a hero-image treatment — too heavy for small functional UI icons. Derive a simplified icon set from the same line-art layer only (no blur/glow) for in-app navigation and functional icons. Reserve the full glass-illustration treatment for onboarding, empty states, and marketing.

---

## 7. Color system

Colors sampled directly from brand reference photography (two overlapping frosted/gradient panel photo), extended into a full UX-usable token system with WCAG-checked contrast variants.

### Distribution rule
Not a standard 60/30/10 split — SHARIT has one job to protect (numbers must be instantly legible) and one brand color to spend carefully.

| Group | Target share of any screen | Rule |
|---|---|---|
| Neutrals | ~88% | Background, cards, borders, text — carries the whole UI |
| Primary action | ~7% | One color only, used consistently for anything interactive |
| Identity + status accents | ~5% combined | Meaning-only — never decorative |

### Tokens

**Neutrals**
| Token | Hex | Use |
|---|---|---|
| App Background | `#FBF6F0` | Base shell, all screens |
| Card / Surface | `#F4D3B3` | Sampled from reference photo — cards, sheets, elevation |
| Border / Divider | `#DFCCC0` | Sampled — hairlines, input borders |
| Text — Secondary | `#72635C` | Timestamps, labels, meta |
| Text — Primary (Ink) | `#221F26` | Body copy, amounts, headings |

**Primary action** — the only interactive brand color; used consistently everywhere
| Token | Hex | Use | Contrast |
|---|---|---|---|
| Primary Fill (button) | `#C45511` | Solid buttons, white text | 4.51:1 white-on-fill |
| Primary Text/Icon | `#9C440E` | Links, active tab, icons on light bg | 4.57:1 |
| Primary Raw (photo) | `#ED7932` | Large hero fills, illustration only — never text | — |

**Identity accent** — restricted to avatars/tags/data-viz; never buttons, never global UI
| Token | Hex | Use | Contrast |
|---|---|---|---|
| Cool Raw (photo) | `#4A86AC` | Avatar rings, chart series, large areas only | — |
| Cool Text-safe | `#37637F` | If cool text is ever needed | 4.54:1 |

**Semantic status** — meaning-only, ~2% of a screen
| Token | Hex | Use | Contrast |
|---|---|---|---|
| Settled Text-safe | `#396577` | Confirmed/paid badges — pair with a check icon, color alone won't read as "success" the way green would | 4.50:1 |
| Settled Raw (photo) | `#78AABF` | Badge background fill only, not text | — |
| Needs Action Fill | `#E22F1B` | Alert buttons, white text | 4.50:1 |
| Needs Action Text | `#B42615` | Error text, overdue labels | 4.58:1 |

### Key decisions worth remembering
- The raw sampled cream reads as too heavy across an entire screen of numbers — promoted to "card surface" rather than "app background"; the true background is a near-white whisper of the same tone.
- Warm/Cool were originally conceived as an equal "your side / their side" pair. For real UI, two competing primary-feeling colors hurts learnability — **Warm is the only interactive/primary color app-wide.** Cool is identity-only (whose avatar, which data series) and never appears on a button or link. This also scales better if SHARIT ever supports more than two people splitting a cost.
- "Settled" deliberately avoids generic fintech-green to stay on-brand — cost of that choice is weaker instant recognition, mitigated by always pairing the badge with an icon, never color alone.

---

## 8. Typography

**Typeface: Poppins.**

Note on this choice, for the record: Poppins is a geometric sans with notably rounded, friendly letterforms — closer to the "playful/toylike" register than the restrained-but-warm recommendation explored earlier in this process (a grotesk/humanist sans with only slight rounding). Since Poppins is the decided direction, the guidance below is about using it in a way that protects precision despite its friendlier default character, rather than fighting the choice.

**Usage rules to protect precision within Poppins:**
- Reserve **Regular/Medium** for body copy and UI labels; use **SemiBold/Bold** for headings, amounts, and anything that needs to read as certain rather than soft. Avoid Poppins Light/Thin for anything functional — thin geometric strokes lose legibility fast at small sizes, especially on the soft gradient backgrounds used in hero/marketing contexts.
- **Numerals carry extra weight in this product** — this is a cost-splitting app; half the UI is numbers. Use tabular (fixed-width) numerals wherever amounts are shown so figures align in lists and don't jitter between screens. Verify Poppins' numeral set is unambiguous at small sizes (6 vs 8, 3 vs 8) before shipping — geometric numeral sets are the most common place this typeface family causes real legibility problems.
- Avoid gradient-filled or multi-color text treatments — keep all type in a single solid ink color (Text Primary/Secondary tokens above). The imagery carries the softness; the type should be the one thing in the system that reads as completely certain. That contrast — softest imagery, most certain type — is the intended expression of warmth × precision, and it only works if type stays flat and solid.
- Keep headline tracking tight and confident rather than loose/airy — loose tracking combined with Poppins' already-rounded letterforms pushes further toward "cute" than the brand wants.

---

## 9. North star references

Three protagonist images anchor the direction (see reference exports):

1. **"The Handoff"** — a pink gradient form pouring into a blue gradient form with no visible seam. Literal thesis image: one thing becoming another, warm becoming cool, no edge you could point to. This is what a shared car *is*, drawn as pure color.
2. **"The Gathering"** — a cluster of small warm spheres orbiting one glowing center. Precision (clean, considered shapes) and warmth (gathered *around* something) at once — the "circle of people you trust," without drawing a person.
3. **"The Overlap"** — stacked, overlapping warm circles. Simplest, most direct expression of shared use: things occupying the same space, taking turns, layered rather than separate. Most flexible workhorse image — scales to icon size and up to hero size.

---

## 10. Image-generation prompt guidelines

For producing brand imagery via Midjourney/Nano Banana/similar:

- Never prompt for "logo," "brand identity," or "app icon" directly — produces generic output. Prompt for the *scene, light, texture, and moment* that embodies the brand feeling instead.
- Keep prompts short (≤15 words as a working default) and draw directly from the vocabulary in §5.
- Append a short consistent style suffix across a session for comparable results, e.g.: *"soft gradient blur, warm-cool contrast, light film grain, no hard edges."*
- Prompt in four groups:
  1. **Threshold moments** — human-scale scenes central to the brand's world (keys, doorways, handoffs, dawn/dusk)
  2. **Pure mesh-gradient studies** — abstract hero imagery, no objects
  3. **Domestic object studies** — tests whether the technique survives contact with SHARIT's actual subject matter (cars, keys, dashboards) — this is the highest-value, riskiest group; run it first
  4. **Pure atmosphere/light** — no subject at all

---

## 11. Open questions / not yet decided

- Whether the mesh-gradient illustration technique holds up applied to a literal car (flagged risk, untested as of this writing).
- Full icon system derived from the illustration line-art layer — not yet built.
- Dark mode token equivalents — not yet defined.
- Whether Cool accent needs a distinct alternate token if SHARIT ever supports groups larger than two people (current system assumes one Warm + one Cool identity slot).
