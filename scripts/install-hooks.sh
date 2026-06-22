#!/bin/sh
# Installe le hook pre-commit de TOVA (REFERENCE-PROJET.md §11).
# Le hook n'est pas versionne par Git : l'installer fait partie du bootstrap.
# A relancer apres tout clone du depot. Git pour Windows execute aussi ce hook.
set -e

HOOK_DIR="$(git rev-parse --git-path hooks)"
mkdir -p "$HOOK_DIR"

cat > "$HOOK_DIR/pre-commit" <<'HOOK'
#!/bin/sh
branch="$(git symbolic-ref --short HEAD 2>/dev/null)"
case "$branch" in
  main|master|dev)
    echo "REFUS : commit direct sur '$branch' interdit (REFERENCE-PROJET.md, section 4)."
    echo "Cree une branche : git checkout -b feature/<axe>-<slug>"
    exit 1
    ;;
esac
HOOK

chmod +x "$HOOK_DIR/pre-commit"
echo "Hook pre-commit installe : $HOOK_DIR/pre-commit"
