<?php

namespace PeterAlaxin\LaravelSecurity\Helpers;

use Symfony\Component\HtmlSanitizer\HtmlSanitizer as SymfonySanitizer;
use Symfony\Component\HtmlSanitizer\HtmlSanitizerConfig;

/**
 * HTML Sanitizer helper for cleaning user input from rich text editors
 *
 * Allows only safe HTML tags and attributes to prevent XSS attacks
 */
class HtmlSanitizer
{
    /**
     * Cached sanitizer instance
     */
    private static ?SymfonySanitizer $sanitizer = null;

    /**
     * Sanitize HTML content
     *
     * @param  string|null  $html  The HTML content to sanitize
     * @return string|null Sanitized HTML or null if input was null
     */
    public static function sanitize(?string $html): ?string
    {
        if ($html === null || $html === '') {
            return $html;
        }

        $sanitizer = self::getSanitizer();

        return $sanitizer->sanitize($html);
    }

    /**
     * Get or create the sanitizer instance
     */
    private static function getSanitizer(): SymfonySanitizer
    {
        if (self::$sanitizer === null) {
            $config = new HtmlSanitizerConfig();

            // Get allowed elements from config
            $allowedElements = config('security.html_sanitizer.allowed_elements', [
                'p', 'br', 'strong', 'b', 'em', 'i', 'u', 's', 'strike',
                'h1', 'h2', 'h3', 'ul', 'ol', 'li', 'a', 'span', 'blockquote',
            ]);

            // Get allowed attributes from config
            $allowedAttributes = config('security.html_sanitizer.allowed_attributes', [
                'a' => ['href', 'target', 'rel'],
                'span' => ['style'],
            ]);

            // Add elements without attributes
            foreach ($allowedElements as $element) {
                if (isset($allowedAttributes[$element])) {
                    $config = $config->allowElement($element, $allowedAttributes[$element]);
                } else {
                    $config = $config->allowElement($element);
                }
            }

            // Get allowed link schemes from config
            $allowedSchemes = config('security.html_sanitizer.allowed_schemes', ['http', 'https', 'mailto']);
            $config = $config->allowLinkSchemes($allowedSchemes);

            // Force security attributes on links
            if (config('security.html_sanitizer.force_link_security', true)) {
                $config = $config->forceAttribute('a', 'rel', 'noopener noreferrer');
                $config = $config->forceAttribute('a', 'target', '_blank');
            }

            self::$sanitizer = new SymfonySanitizer($config);
        }

        return self::$sanitizer;
    }

    /**
     * Clear cached sanitizer (useful after config changes)
     */
    public static function clearCache(): void
    {
        self::$sanitizer = null;
    }

    /**
     * Sanitize and strip all HTML, returning plain text
     *
     * @param  string|null  $html  The HTML content to strip
     * @return string|null Plain text or null if input was null
     */
    public static function stripAll(?string $html): ?string
    {
        if ($html === null || $html === '') {
            return $html;
        }

        return strip_tags($html);
    }
}
