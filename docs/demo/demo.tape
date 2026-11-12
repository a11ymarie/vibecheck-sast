# The README GIF: scan an app, fix a few things, re-check.
#
# Re-record it (needs vhs, ttyd, ffmpeg and a color emoji font):
#   ./demo.sh --playground ~/code/my-app        # if it doesn't exist yet
#   vhs docs/demo/demo.tape                     # run from the vibecheck-sast folder
# Afterwards, reset the practice app with: git -C ~/code/my-app checkout -- .

Output docs/demo/demo.gif

Set Shell "bash"
Set FontFamily "DejaVu Sans Mono"
Set FontSize 15
Set Width 1240
Set Height 540
Set Padding 26
Set Theme "Dracula"
Set TypingSpeed 40ms
Set Framerate 24

Hide
Type "export PS1='$ ' PYTHONDONTWRITEBYTECODE=1 && clear"
Enter
Sleep 500ms
Show

# 1. Scan an app.
Type "./vibecheck --quick ~/code/my-app"
Sleep 600ms
Enter
Wait+Screen@40s /Fix tasks:/
Sleep 5s

# 2. Hand the task list to an AI assistant (stood in for by docs/demo/apply-fixes.py).
Type "# hand fix-tasks.md to your AI assistant (in Claude Code: /vibecheck)"
Sleep 1.2s
Enter
Sleep 1s
Hide
Type "python3 docs/demo/apply-fixes.py ~/code/my-app && clear"
Enter
Sleep 1s
Show

# 3. Re-check: what's fixed, what's still open, what's new.
Type "./vibecheck --quick --compare last ~/code/my-app"
Sleep 600ms
Enter
Wait+Screen@40s /Fix tasks:/
Sleep 7s
