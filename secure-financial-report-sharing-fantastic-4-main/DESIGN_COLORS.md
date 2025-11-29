# 🎨 Zenith Design Color Palette

## Color Variables

All colors are defined in CSS custom properties in `templates/base.html`:

```css
:root {
    --heading-white: #F9FAFB;        /* Headings like card titles */
    --body-white: #D1D5DB;           /* Body text and descriptions */
    --border-gray-purple: #37333F;   /* Borders (login, cards on hover) */
    --primary-violet: #A78BFA;       /* Brand color, buttons, "Zenith" text */
    --smooth-black: #0E1111;         /* Main background, button text */
    --subtle-bg-dark-violet: #1F1D24; /* Card backgrounds */
}
```

## Usage Guide

### Headings (Feature Titles, Important Text)
- **Color**: `#F9FAFB` (Heading White)
- **Usage**: Card titles, section headings
- **Class**: `.feature-title`, `.hero-title`

### Body Text (Descriptions)
- **Color**: `#D1D5DB` (Body White)
- **Usage**: Descriptions, paragraphs, less important text
- **Class**: `.feature-description`, `.hero-subtitle`

### Borders
- **Color**: `#37333F` (Border Gray-Purple)
- **Usage**: Card borders on hover, input borders, dividers
- **Class**: `.btn-secondary`, `.feature-card:hover`

### Primary Action (Zenith Brand)
- **Color**: `#A78BFA` (Primary Violet)
- **Usage**: "Zenith" logo, "Get Started" button background, highlights
- **Class**: `.btn-primary`, `.hero-title`

### Main Background
- **Color**: `#0E1111` (Smooth Black)
- **Usage**: Page background, text on bright buttons
- **Element**: `body`, `.btn-primary` text

### Card Background
- **Color**: `#1F1D24` (Subtle Background Dark Violet)
- **Usage**: Feature cards, content boxes
- **Class**: `.feature-card`

## Design Principles

1. **High Contrast**: White text on dark backgrounds for readability
2. **Subtle Hierarchy**: Heading White (#F9FAFB) vs Body White (#D1D5DB)
3. **Accent Color**: Violet (#A78BFA) used sparingly for emphasis
4. **Depth**: Card backgrounds slightly lighter than page background
5. **Smooth Transitions**: All interactive elements have 0.3s ease transitions

## Typography

### Font Families
- **Headings**: Exo 2 (via Google Fonts)
  - Used for: h1-h6, .hero-title, .feature-title, navbar logo
  - Weights: 400, 500, 600, 700, 800
  
- **Body Text**: Open Sans (via Google Fonts)
  - Used for: body text, paragraphs, buttons, descriptions
  - Weights: 300, 400, 500, 600, 700

### Font Weights
- **Hero Title**: 800 (Extra Bold)
- **Feature Titles**: 600 (Semi-Bold)
- **Body Text**: 400 (Regular)
- **Buttons**: 600 (Semi-Bold)

### Letter Spacing
- **Large headings**: -2px (tighter for impact)

## Spacing

- **Hero Section Padding**: 8rem top, 6rem bottom
- **Card Padding**: 2.5rem all sides
- **Button Padding**: 0.875rem vertical, 2rem horizontal
- **Grid Gap**: 2rem between cards

## Interactive States

### Buttons
- **Hover**: `translateY(-2px)` + glow shadow
- **Primary Hover**: Lighter violet (#b89dfa)
- **Secondary Hover**: Subtle background + violet border

### Cards
- **Hover**: `translateY(-5px)` + border + shadow
- **Rest State**: Transparent border
