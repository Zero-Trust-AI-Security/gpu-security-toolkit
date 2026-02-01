#!/usr/bin/env python3
"""
GPU Security Toolkit - Document Splitter
Automatically splits large markdown documents into mdBook chapters
"""

import re
import os
from pathlib import Path

def split_by_h2_headers(input_file, output_dir, prefix=""):
    """Split markdown file by ## headers into separate chapter files"""
    
    print(f"\nProcessing: {input_file}")
    print(f"Output to: {output_dir}/")
    
    if not os.path.exists(input_file):
        print(f"  ⚠ File not found, skipping")
        return
    
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Split on ## headers (H2 level)
    sections = re.split(r'^## (.+)$', content, flags=re.MULTILINE)
    
    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # First section (before any H2) becomes README.md
    intro = sections[0].strip()
    if intro:
        readme_path = Path(output_dir) / "README.md"
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(intro + "\n")
        print(f"  ✓ {readme_path}")
    
    # Process each H2 section
    file_count = 0
    for i in range(1, len(sections), 2):
        if i+1 >= len(sections):
            break
            
        title = sections[i].strip()
        body = sections[i+1].strip()
        
        # Create filename from title
        filename = title.lower()
        # Remove special characters
        filename = re.sub(r'[^\w\s-]', '', filename)
        # Replace spaces/underscores with hyphens
        filename = re.sub(r'[-\s_]+', '-', filename)
        # Add prefix if provided
        if prefix:
            filename = f"{prefix}-{filename}"
        filename = f"{filename}.md"
        
        # Write chapter file
        filepath = Path(output_dir) / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# {title}\n\n{body}\n")
        
        print(f"  ✓ {filepath}")
        file_count += 1
    
    print(f"  Created {file_count} chapter files")

def main():
    """Split all GPU security documentation into mdBook structure"""
    
    print("=" * 60)
    print("GPU Security Toolkit - Content Splitter")
    print("=" * 60)
    
    # Split each major document
    documents = [
        ('nvidia_gpu_security_controls.md', 'src/controls', ''),
        ('gpu_threat_model_frameworks.md', 'src/threats', ''),
        ('gpu_use_case_security_guide.md', 'src/use-cases', ''),
        ('gpu_forensics_complete_guide.md', 'src/forensics', ''),
        ('gpu_forensics_incident_response.md', 'src/forensics', 'ir'),
    ]
    
    total_files = 0
    for input_file, output_dir, prefix in documents:
        if os.path.exists(input_file):
            split_by_h2_headers(input_file, output_dir, prefix)
            total_files += len(list(Path(output_dir).glob('*.md')))
    
    print("\n" + "=" * 60)
    print(f"✓ Content splitting complete!")
    print(f"✓ Total files created: {total_files}")
    print("=" * 60)
    print("\nNext steps:")
    print("  1. Review files in src/ directories")
    print("  2. Update src/SUMMARY.md with new file paths")
    print("  3. Run: mdbook build")
    print("  4. Run: mdbook serve --open")
    print("")

if __name__ == "__main__":
    main()
