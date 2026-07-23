import { ThreeMFData, ThreeMFAmsRequirements, ThreeMFPlateObjects } from './types.js';
export { ThreeMFData };
export declare function parse3MF(filePath: string): Promise<ThreeMFData>;
export declare function extractBambuTemplateSettings(filePath: string, outputDir: string): Promise<string>;
export declare function analyze3MFAmsRequirements(filePath: string, plateIndex?: number): Promise<ThreeMFAmsRequirements>;
export declare function analyze3MFPlateObjects(filePath: string, plateIndex?: number): Promise<ThreeMFPlateObjects>;
