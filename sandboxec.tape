Require gum
Require glow

Output dist/sandboxec.gif
# Output dist/sandboxec.mp4
# Output dist/sandboxec.mov
Output dist/frames/

Set WindowBar Colorful
Set TypingSpeed 50ms
Set FontSize 20
Set Width 980
Set Height 512
Set Margin 20
Set MarginFill "#0d1117"
Set BorderRadius 10
Set Framerate 120
Set FontFamily "JetBrains Mono"
Set Theme "Dark Pastel"

Type "sandboxec --fs rx:/usr echo ayo, wangsaf?"
Sleep 250ms
Enter
Sleep 250ms

Type "sandboxec --fs rx:/usr -- head -3 README.md"
Sleep 250ms
Enter
Sleep 250ms

Type "sandboxec --fs rx:/usr --fs r:$PWD -- head -3 README.md"
Sleep 250ms
Enter
Sleep 2s
Type "clear"
Enter

Type "sandboxec --fs rx:/usr -- touch /tmp/foo"
Sleep 250ms
Enter
Sleep 250ms

Type "sandboxec --fs rx:/usr --fs rw:/tmp -- touch /tmp/foo"
Sleep 250ms
Enter
Sleep 2s
Type "clear"
Enter

Type "sandboxec --fs rx:/usr -- cat /etc/passwd"
Sleep 250ms
Enter
Sleep 250ms

Type "sandboxec --fs rx:/usr -- cat ~/.ssh/id_rsa"
Sleep 250ms
Enter
Sleep 2s
Type "clear"
Enter

Type "sandboxec --fs rx:/ -- curl -v https://httpbin.org/status/200"
Sleep 250ms
Enter
Sleep 2s
Type "clear"
Enter

Type `sandboxec --fs rx:/ --net c:443 -- \`
Enter
Type "  curl -i https://httpbin.org/status/200"
Sleep 250ms
Enter
Sleep 5s

# Type "sandboxec --config profiles/claude.yaml -- claude"
# Sleep 250ms
# Enter
# Sleep 5s
