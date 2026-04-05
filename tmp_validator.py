import sys
from html.parser import HTMLParser

class MyHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        
    def handle_starttag(self, tag, attrs):
        if tag not in ['img', 'br', 'hr', 'input', 'meta', 'link']:
            self.tags.append(tag)
            
    def handle_endtag(self, tag):
        if tag not in ['img', 'br', 'hr', 'input', 'meta', 'link']:
            if len(self.tags) == 0:
                print(f"Extra closing tag: {tag} at line {self.getpos()[0]}")
            elif self.tags[-1] == tag:
                self.tags.pop()
            else:
                print(f"Mismatch: expected {self.tags[-1]}, got {tag} at line {self.getpos()[0]}")
                # Try to recover by finding the matching tag
                for i in range(len(self.tags)-1, -1, -1):
                    if self.tags[i] == tag:
                        self.tags = self.tags[:i]
                        break

with open(r"c:\Users\Shaik Azeeza Farhana\Downloads\sam_tool\templates\dashboard.html", "r", encoding="utf-8") as f:
    content = f.read()
    
# extremely basic stripping of Django template tags so they don't break parser
import re
content = re.sub(r'\{%.*?%\}', '', content)
content = re.sub(r'\{\{.*?\}\}', '', content)

parser = MyHTMLParser()
parser.feed(content)

print("Remaining open tags:", parser.tags)
