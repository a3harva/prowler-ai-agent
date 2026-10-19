import {
  createContext,
  useCallback,
  useContext,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { flushSync } from "react-dom";

export type Theme = "light" | "dark";

const STORAGE_KEY = "prowler-theme";

/** Kept in step with the `theme-reveal` keyframes in `index.css`. A duration
 *  lives in both places because CSS owns the easing and JS owns when the
 *  transition object is allowed to settle; they only have to agree loosely,
 *  and the browser — not this number — decides when the animation ends. */
const REVEAL_MS = 520;

/** `Document.startViewTransition` is not in TypeScript's DOM lib at 5.7, so
 *  it is narrowed here rather than cast away at each call site. Only the two
 *  members this file actually uses are declared — a fuller shim would be a
 *  claim about an API we don't exercise. */
interface ViewTransition {
  finished: Promise<void>;
  skipTransition: () => void;
}
type ViewTransitionDocument = Document & {
  startViewTransition?: (callback: () => void) => ViewTransition;
};

/** Defaults to light: the prowler agent theme is the light one, and dark is the
 *  counterpart a user opts into. Deliberately does NOT consult
 *  `prefers-color-scheme` — the console is a document-shaped product whose
 *  own output (the compliance report, and its print path) is light, so the
 *  OS preference would silently hand most visitors a theme that disagrees
 *  with what they are about to print.
 *
 *  `index.html` runs a pre-paint script reading this same key, so a dark
 *  user's first frame is already dark. That script only reads; this module
 *  stays the single writer. */
function readStoredTheme(): Theme {
  try {
    return localStorage.getItem(STORAGE_KEY) === "dark" ? "dark" : "light";
  } catch {
    // Storage can throw outright in a locked-down context, and this runs
    // during the initial render — an exception here is a blank app, not a
    // missing preference.
    return "light";
  }
}

function prefersReducedMotion(): boolean {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** The reveal geometry, as PERCENTAGES rather than pixels — and that is a
 *  correctness fix, not a style preference.
 *
 *  `::view-transition-new(root)` does not lay out in CSS pixels here. Measured
 *  in Chrome on a `devicePixelRatio: 2` display: feeding it the viewport
 *  centre (720px, 361px of a 1440×722 viewport) drew the circle at (360, 180)
 *  — exactly half, i.e. the pseudo-element's box is the snapshot in DEVICE
 *  pixels. So a pixel offset taken from `getBoundingClientRect` lands in the
 *  wrong place on every non-1 DPR screen, which is most of them, while
 *  looking perfect on the 1× display it was written on.
 *
 *  Percentages resolve against that same box whatever its scale, so they are
 *  invariant. The radius is the fiddly one: a percentage in `circle()`
 *  resolves against `√(w² + h²) / √2` of the reference box, so the pixel
 *  radius is converted through the CSS-pixel version of that same expression.
 *  Both numerator and denominator scale together, so the ratio survives.
 *
 *  The radius itself reaches the FURTHEST viewport corner. Anything smaller
 *  leaves a wedge of the outgoing theme behind at the end of the sweep, which
 *  reads as a rendering bug rather than as a shorter animation. */
interface Reveal {
  x: string;
  y: string;
  r: string;
}

function revealGeometry(x: number, y: number): Reveal {
  const width = window.innerWidth;
  const height = window.innerHeight;
  const radius = Math.hypot(Math.max(x, width - x), Math.max(y, height - y));
  const reference = Math.hypot(width, height) / Math.SQRT2;

  return {
    x: `${(x / width) * 100}%`,
    y: `${(y / height) * 100}%`,
    r: `${(radius / reference) * 100}%`,
  };
}

interface ThemeContextValue {
  theme: Theme;
  /** `origin` is the element the change was triggered from — the circular
   *  reveal grows out of its centre. Omit it (or pass nothing) and the theme
   *  swaps without animation, which is also what happens when the browser
   *  has no View Transitions or the user asked for reduced motion. */
  setTheme: (theme: Theme, origin?: Element | null) => void;
  toggleTheme: (origin?: Element | null) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(readStoredTheme);
  const transitionRef = useRef<ViewTransition | null>(null);

  // A LAYOUT effect, not a passive one, and that is the whole mechanism.
  // `startViewTransition` snapshots the page the moment its callback
  // returns, so the class has to be on <html> by then. `flushSync` below
  // guarantees layout effects have run; passive effects carry no such
  // guarantee, and a passive version of this animates the old theme into
  // itself — a visible sweep that changes nothing.
  useLayoutEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // Same reasoning as the read: the theme still applies for this
      // session, it just won't survive a reload.
    }
  }, [theme]);

  const setTheme = useCallback((next: Theme, origin?: Element | null) => {
    const doc = document as ViewTransitionDocument;
    const root = document.documentElement;

    if (!origin || !doc.startViewTransition || prefersReducedMotion()) {
      setThemeState(next);
      return;
    }

    // A second click mid-sweep would otherwise start a transition while one
    // is running: the browser aborts the first, and the abandoned snapshot
    // flashes. Skipping the running one to its end first makes rapid
    // toggling look like what it is — a fast series of complete swaps.
    transitionRef.current?.skipTransition();

    const rect = origin.getBoundingClientRect();
    const reveal = revealGeometry(rect.left + rect.width / 2, rect.top + rect.height / 2);

    root.style.setProperty("--reveal-x", reveal.x);
    root.style.setProperty("--reveal-y", reveal.y);
    root.style.setProperty("--reveal-r", reveal.r);
    root.style.setProperty("--reveal-ms", `${REVEAL_MS}ms`);
    // Gates the keyframes in index.css. Without it every view transition the
    // app might ever start — not just this one — would get the wipe.
    root.classList.add("theme-reveal");

    const transition = doc.startViewTransition(() => {
      flushSync(() => setThemeState(next));
    });
    transitionRef.current = transition;

    transition.finished
      .catch(() => {
        // An interrupted transition rejects. The theme itself has already
        // been committed by the callback, so there is nothing to undo —
        // only the marker class to clear, which happens either way.
      })
      .finally(() => {
        if (transitionRef.current === transition) {
          transitionRef.current = null;
          root.classList.remove("theme-reveal");
        }
      });
  }, []);

  const toggleTheme = useCallback(
    (origin?: Element | null) => setTheme(theme === "dark" ? "light" : "dark", origin),
    [theme, setTheme],
  );

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) throw new Error("useTheme must be used within ThemeProvider");
  return context;
}
