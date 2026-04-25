
import numpy as np
from PIL import Image
from scipy.stats import chisquare
import math
import os

class SecurityAnalyzer:
    def __init__(self):
        self.analysis_results = {}
    
    def analyze_stego_image(self, original_path, stego_path):
        """Analyze security of stego image."""
        analysis = {}
        
        # 1. Statistical Analysis
        analysis['statistical'] = self.statistical_analysis(original_path, stego_path)
        
        # 2. Entropy Analysis
        analysis['entropy'] = self.entropy_analysis(stego_path)
        
        # 3. RS Analysis (Resistance to Visual Attacks)
        analysis['rs_detect'] = self.rs_analysis(stego_path)
        
        # 4. Chi-square Analysis
        analysis['chi_square'] = self.chi_square_analysis(stego_path)
        
        # 5. Visual Attack Simulation (Enhanced with comparison)
        analysis['visual_attack'] = self.visual_attack_simulation(stego_path, original_path)
        
        # 6. Calculate Final Score
        self.calculate_security_score(analysis)
        
        return analysis

    def statistical_analysis(self, original_path, stego_path):
        """Perform statistical analysis on images (MSE, PSNR)."""
        try:
            img1 = Image.open(original_path).convert('RGB')
            img2 = Image.open(stego_path).convert('RGB')
            
            arr1 = np.array(img1)
            arr2 = np.array(img2)
            
            if arr1.shape != arr2.shape:
                return {"error": "Dimensions mismatch", "psnr": 0, "mse": 9999}

            mse = np.mean((arr1 - arr2) ** 2)
            if mse == 0:
                psnr = 100  # Perfect match
            else:
                psnr = 20 * math.log10(255.0 / math.sqrt(mse))
                
            return {
                "mse": round(mse, 4),
                "psnr": round(psnr, 2)
            }
        except Exception as e:
            return {"error": str(e), "psnr": 0}

    def entropy_analysis(self, image_path):
        """Calculate image entropy."""
        try:
            img = Image.open(image_path).convert('L')  # Convert to grayscale
            histogram = img.histogram()
            histogram_length = sum(histogram)
            
            samples_probability = [float(h) / histogram_length for h in histogram]
            
            entropy = -sum([p * math.log(p, 2) for p in samples_probability if p != 0])
            
            return round(entropy, 4)
        except Exception as e:
            return 0

    def chi_square_analysis(self, image_path):
        """Perform Chi-Square attack detection."""
        try:
            # Simple Chi-square for LSB
            img = Image.open(image_path).convert('RGB')
            arr = np.array(img).flatten()
            
            # Count pair of values (2k, 2k+1)
            counts = np.bincount(arr, minlength=256)
            
            expected = []
            observed = []
            
            for i in range(0, 256, 2):
                pair_sum = (counts[i] + counts[i+1]) / 2
                expected.extend([pair_sum, pair_sum])
                observed.extend([counts[i], counts[i+1]])
                
            chi_val, p_val = chisquare(observed, f_exp=expected)
            
            return {
                "chi_value": round(chi_val, 2),
                "p_value": round(p_val, 4), 
                "detected": p_val < 0.05  # If p < 0.05, likely stego
            }
        except Exception as e:
            return {"error": str(e), "chi_value": 0, "p_value": 1.0}

    def rs_analysis(self, image_path):
        """RS Steganalysis (Placeholder for advanced detection)."""
        # A full RS implementation is complex; this is a simplified placeholder
        # In a real scenario, this would check for RS groups flipping.
        return False # Assessing as 'Not Detected' for now unless deep analysis implemented

    def visual_attack_simulation(self, stego_path, original_path=None):
        """Simulate Visual Attack (Bit Plane Slicing)."""
        try:
            # Analyze Stego Image
            img = Image.open(stego_path).convert('L')
            arr = np.array(img)
            lsb_plane = (arr & 1) * 255
            stego_variance = np.var(lsb_plane)
            
            result = {
                "lsb_variance": round(stego_variance, 2),
                "suspicious": False
            }

            # If Original is provided, compare variances (Differential Analysis)
            if original_path:
                img_orig = Image.open(original_path).convert('L')
                arr_orig = np.array(img_orig)
                lsb_plane_orig = (arr_orig & 1) * 255
                orig_variance = np.var(lsb_plane_orig)
                
                result["original_variance"] = round(orig_variance, 2)
                # If variance increased significantly (e.g., > 50%), it's suspicious
                if stego_variance > (orig_variance * 1.5) and stego_variance > 1000:
                    result["suspicious"] = True
            else:
                # Fallback absolute threshold
                result["suspicious"] = stego_variance > 2500 # Adjusted threshold
                
            return result
        except Exception as e:
            return {"error": str(e)}

    def calculate_security_score(self, analysis):
        """Calculate overall security score (0-100) with granular deductions."""
        score = 100
        reasons = []
        
        # 1. PSNR Analysis (Weight: 30 points)
        # PSNR > 50: Excellent (0 deduction)
        # PSNR 40-50: Good (-5)
        # PSNR 30-40: Fair (-15)
        # PSNR < 30: Poor (-30)
        stat = analysis.get('statistical', {})
        psnr = stat.get('psnr', 0)
        
        if psnr >= 50:
            pass # Excellent quality
        elif psnr >= 40:
            score -= 5
            reasons.append("Slight quality reduction detected (PSNR < 50)")
        elif psnr >= 30:
            score -= 15
            reasons.append("Noticeable quality loss (PSNR < 40)")
        else:
            score -= 30
            reasons.append("Significant image distortion (PSNR < 30)")
            
        # 2. Chi-Square Attack (Weight: 40 points)
        # p < 0.01: Highly likely stego (-40)
        # p < 0.05: Likely stego (-20)
        # p > 0.05: Clean (0)
        chi = analysis.get('chi_square', {})
        p_val = chi.get('p_value', 1.0)
        
        if p_val < 0.01:
            score -= 40
            reasons.append("Statistical attack strongly detected (High Confidence)")
        elif p_val < 0.05:
            score -= 20
            reasons.append("Statistical irregularities detected (Medium Confidence)")
            
        # 3. Visual/Variance Attack (Weight: 30 points)
        visual = analysis.get('visual_attack', {})
        if visual.get('suspicious'):
            score -= 30
            reasons.append("Abnormal noise in LSB plane detected")
            
        final_score = max(10, score) # Clamp to 10 to avoid 0 score panic
        
        # Format the reasons for UI display WITH VALUES for debugging
        debug_info = f"\\nDEBUG: PSNR={psnr}, Chi-p={p_val:.4f}, Visual={visual.get('suspicious', False)}"
        analysis['score_reasons'] = reasons + [debug_info]
        analysis['final_score'] = final_score
        
        return final_score