/**
 * Template renderer for agent system prompts.
 * 
 * This module handles rendering agent template files by replacing placeholders
 * with actual tool strings based on what tools the user has installed.
 * 
 * Template syntax:
 * - {{PLACEHOLDER_NAME}}: Replaced with tool string if tool is installed, empty string otherwise
 * - {{SECTION_NAME_START}} ... {{SECTION_NAME_END}}: Section markers, removed if section is empty
 */

import { TOOL_STRINGS, ToolStringSet } from '../config/tool-strings.js';

export interface RenderContext {
  installedTools: string[];      // All tools user chose to install (docker, python, ruby tools)
  installedMcpServers: string[]; // MCP servers user chose to install
}

/**
 * Normalize tool name for matching (handle variations like tree-sitter vs treesitter)
 */
function normalizeToolName(name: string): string {
  return name.toLowerCase().replace(/-/g, '').replace(/_/g, '');
}

/**
 * Check if a tool is installed (handles name variations)
 */
function isToolInstalled(toolName: string, context: RenderContext): boolean {
  const normalizedToolName = normalizeToolName(toolName);
  
  // Check in installed tools
  const inTools = context.installedTools.some(
    t => normalizeToolName(t) === normalizedToolName
  );
  
  // Check in installed MCP servers
  const inMcp = context.installedMcpServers.some(
    m => normalizeToolName(m) === normalizedToolName
  );
  
  return inTools || inMcp;
}

/**
 * Extract tool name from placeholder name
 * E.g., TOOL_LIST_OPENGREP -> opengrep, TOOL_USAGE_CODEQL -> codeql
 */
function extractToolNameFromPlaceholder(placeholder: string): string | null {
  // Pattern: TOOL_{TYPE}_{TOOLNAME}
  const match = placeholder.match(/^TOOL_[A-Z]+_([A-Z0-9]+)$/);
  if (match) {
    return match[1].toLowerCase();
  }
  return null;
}

/**
 * Find all placeholders in template content
 */
function findPlaceholders(content: string): string[] {
  const regex = /\{\{([A-Z_0-9]+)\}\}/g;
  const placeholders: string[] = [];
  let match;
  
  while ((match = regex.exec(content)) !== null) {
    if (!placeholders.includes(match[1])) {
      placeholders.push(match[1]);
    }
  }
  
  return placeholders;
}

/**
 * Find all section markers in template content
 * Returns pairs of [startMarker, endMarker]
 */
function findSectionMarkers(content: string): [string, string][] {
  const regex = /\{\{SECTION_([A-Z_0-9]+)_START\}\}/g;
  const sections: [string, string][] = [];
  let match;
  
  while ((match = regex.exec(content)) !== null) {
    const sectionName = match[1];
    sections.push([
      `{{SECTION_${sectionName}_START}}`,
      `{{SECTION_${sectionName}_END}}`
    ]);
  }
  
  return sections;
}

/**
 * Check if a section contains meaningful tool content after placeholder replacement.
 * A section is considered empty if:
 * - It contains only whitespace, or
 * - It contains only headers/static text but no actual tool-related content
 * 
 * We detect this by checking if all TOOL_ placeholders in the original section
 * were replaced with empty strings (meaning no tools were installed for that section).
 */
function isSectionEmpty(originalSection: string, renderedSection: string): boolean {
  // Find all TOOL_ placeholders that were in the original section
  const placeholderRegex = /\{\{(TOOL_[A-Z_0-9]+)\}\}/g;
  const placeholders: string[] = [];
  let match;
  
  while ((match = placeholderRegex.exec(originalSection)) !== null) {
    placeholders.push(match[1]);
  }
  
  // If there were no placeholders, section is not empty (it's static content)
  if (placeholders.length === 0) {
    return false;
  }
  
  // Check if the rendered section has any non-whitespace content 
  // beyond just the static header text
  // We do this by comparing: if all placeholders were replaced with empty strings,
  // the rendered content would only be the static text
  
  // Get the static text by removing all placeholders from original
  const staticText = originalSection.replace(placeholderRegex, '').trim();
  const renderedText = renderedSection.trim();
  
  // If the rendered section equals just the static text (headers etc),
  // then all tools were empty and we should remove the section
  // Normalize whitespace for comparison
  const normalizedStatic = staticText.replace(/\s+/g, ' ');
  const normalizedRendered = renderedText.replace(/\s+/g, ' ');
  
  return normalizedRendered === normalizedStatic || renderedText.length === 0;
}

/**
 * Remove empty sections from content
 * A section is considered empty if all tool placeholders in it were replaced with empty strings
 */
function removeEmptySections(originalContent: string, renderedContent: string): string {
  const sections = findSectionMarkers(originalContent);
  let result = renderedContent;
  
  for (const [startMarker, endMarker] of sections) {
    // Find section in original content
    const origStartIdx = originalContent.indexOf(startMarker);
    const origEndIdx = originalContent.indexOf(endMarker);
    
    // Find section in rendered content
    const rendStartIdx = result.indexOf(startMarker);
    const rendEndIdx = result.indexOf(endMarker);
    
    if (origStartIdx !== -1 && origEndIdx !== -1 && 
        rendStartIdx !== -1 && rendEndIdx !== -1) {
      
      const originalSection = originalContent.substring(
        origStartIdx + startMarker.length,
        origEndIdx
      );
      const renderedSection = result.substring(
        rendStartIdx + startMarker.length,
        rendEndIdx
      );
      
      if (isSectionEmpty(originalSection, renderedSection)) {
        // Remove the entire section including markers
        result = result.substring(0, rendStartIdx) + result.substring(rendEndIdx + endMarker.length);
      } else {
        // Keep the content but remove the markers
        result = result.replace(startMarker, '').replace(endMarker, '');
      }
    }
  }
  
  return result;
}

/**
 * Clean up excessive blank lines and empty placeholder lines
 */
function cleanupWhitespace(content: string): string {
  // Split into lines for processing
  const lines = content.split('\n');
  const result: string[] = [];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmedLine = line.trim();
    
    // If line has content, keep it (with trailing whitespace removed)
    if (trimmedLine.length > 0) {
      result.push(line.trimEnd());
      continue;
    }
    
    // Line is empty/whitespace - decide if we should keep it
    
    // Don't add empty line if the previous result line is also empty
    // (this collapses multiple consecutive empty lines into one)
    if (result.length > 0 && result[result.length - 1].trim().length === 0) {
      continue;
    }
    
    // Check if we're inside a list context (previous line starts with list marker)
    // and next non-empty line also starts with list marker
    // If so, skip this empty line as it breaks the list
    const prevLine = result.length > 0 ? result[result.length - 1] : '';
    const nextNonEmptyLine = lines.slice(i + 1).find(l => l.trim().length > 0) || '';
    
    const listPatterns = [/^\s*-\s/, /^\s*\d+\.\s/, /^\s*\*\s/]; // -, 1., *
    const prevIsList = listPatterns.some(p => p.test(prevLine));
    const nextIsList = listPatterns.some(p => p.test(nextNonEmptyLine));
    
    // If both prev and next are list items, skip this empty line
    if (prevIsList && nextIsList) {
      continue;
    }
    
    // Keep single empty lines for paragraph separation
    result.push('');
  }
  
  // Ensure file ends with single newline
  while (result.length > 0 && result[result.length - 1] === '') {
    result.pop();
  }
  
  return result.join('\n') + '\n';
}

/**
 * Get the replacement string for a placeholder
 */
function getPlaceholderReplacement(
  agentName: string,
  placeholder: string,
  context: RenderContext
): string {
  const agentStrings = TOOL_STRINGS[agentName];
  if (!agentStrings) {
    return '';
  }
  
  // Search through all tools for this agent to find the placeholder
  for (const [toolName, toolStrings] of Object.entries(agentStrings)) {
    if (placeholder in toolStrings) {
      // Found the placeholder, check if tool is installed
      if (isToolInstalled(toolName, context)) {
        return toolStrings[placeholder];
      } else {
        return '';
      }
    }
  }
  
  return '';
}

/**
 * Main template rendering function
 * 
 * @param agentName - Name of the agent (e.g., 'MrZeroMapperOS')
 * @param templateContent - Raw template content with placeholders
 * @param context - Installation context with lists of installed tools
 * @returns Rendered markdown content with placeholders replaced
 */
export function renderAgentTemplate(
  agentName: string,
  templateContent: string,
  context: RenderContext
): string {
  let result = templateContent;
  
  // Step 1: Find all placeholders
  const placeholders = findPlaceholders(result);
  
  // Step 2: Replace each placeholder
  for (const placeholder of placeholders) {
    // Skip section markers - they're handled separately
    if (placeholder.startsWith('SECTION_')) {
      continue;
    }
    
    const replacement = getPlaceholderReplacement(agentName, placeholder, context);
    result = result.replace(new RegExp(`\\{\\{${placeholder}\\}\\}`, 'g'), replacement);
  }
  
  // Step 3: Remove empty sections (pass original template for comparison)
  result = removeEmptySections(templateContent, result);
  
  // Step 4: Clean up whitespace
  result = cleanupWhitespace(result);
  
  return result;
}

/**
 * Check if an agent has a template (vs static file)
 */
export function agentHasTemplate(agentName: string): boolean {
  // Agents with templates are those defined in TOOL_STRINGS
  // MrZeroEnvBuilder is static (no tools in prompt)
  return agentName in TOOL_STRINGS;
}
