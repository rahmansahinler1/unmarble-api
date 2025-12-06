from PIL import Image
from google import genai
from google.genai import types
from dotenv import load_dotenv
import io
import os

class ImageFunctions:
    def __init__(self):
        load_dotenv()
        self.client = genai.Client(
            api_key=os.getenv("GEMINI_API_KEY"),
        )
        self.model = "gemini-2.5-flash-image"
        self.max_preview_size = (400, 500)

    def create_preview(self, image_bytes):
        image = Image.open(io.BytesIO(image_bytes))
        image.thumbnail(self.max_preview_size, Image.LANCZOS)
        output = io.BytesIO()
        image.save(output, format='WEBP', quality=100, method=6)
        return output.getvalue()

    def design_image(self, yourself_image_base64, clothing_image_base64):
        main_prompt = f"""
        CLOTHING VIRTUAL TRY-ON - PRECISE IMPLEMENTATION GUIDE

        PRIMARY OBJECTIVE:
        Combine two images to create a realistic virtual try-on result. Image 1 contains a person. Image 2 contains a clothing item (either standalone or worn by a model).

        CRITICAL RULES - CLOTHING ITEM PRESERVATION:
        1. Extract the clothing item from Image 2 with ABSOLUTE PRECISION
        2. The clothing item must remain COMPLETELY UNCHANGED - no additions, modifications, or alterations to its:
        - Original design and structure
        - Fabric patterns and textures
        - Colors and color placement
        - Decorative elements (buttons, zippers, pockets, embroidery)
        - Cut and silhouette
        - Any design details
        3. If Image 2 shows clothing on a model, extract ONLY the clothing item - completely remove the model
        4. Do not add any design elements that don't exist in Image 2, even if they seem logical or complementary

        CLOTHING LAYER LOGIC:
        1. Analyze what the person in Image 1 is currently wearing
        2. Apply intelligent clothing replacement based on garment type:
        - If Image 2 is a TOP (shirt, blouse, sweater, jacket): Replace the existing top, keep bottom garments visible
        - If Image 2 is a BOTTOM (pants, skirt, shorts): Remove existing bottom garments and show appropriate body parts (legs for skirts/shorts, covered legs for pants)
        - If Image 2 is a DRESS: Replace both top and bottom with the dress, show appropriate body parts. Remove the older clothings, just show the dress.
        - If Image 2 is OUTERWEAR (coat, jacket): Layer over existing clothing or replace top layer
        3. NEVER layer bottoms over existing bottoms (e.g., skirt over jeans is incorrect - remove jeans and show legs)
        4. NEVER keep incompatible clothing visible beneath (e.g., if adding a dress, don't show pants underneath)

        HANDLING UNREALISTIC COMBINATIONS:
        When the clothing item from Image 2 creates an incomplete outfit with what's in Image 1:
        1. If Image 2 is PANTS/SHORTS/SKIRT and Image 1 has a full dress:
        - Replace the dress bottom with the pants/skirt/shorts
        - Generate a neutral, plain black or white basic fitted t-shirt for the top
        - Ensure the t-shirt is simple, solid color, no patterns or logos
        2. If Image 2 is a TOP and Image 1 has a full dress:
        - Replace the dress top with the new top
        - Generate neutral, plain black or dark fitted pants/leggings for the bottom
        3. Default neutral items should be:
        - Solid colors (black, white, or neutral tones)
        - Simple, fitted silhouettes
        - No patterns, logos, or decorative elements
        - Appropriate for the style context

        BODY AND FACE PRESERVATION:
        1. Preserve the person's face, body proportions, posture, and all human features EXACTLY as in Image 1
        2. NEVER modify, stylize, or alter:
        - Facial features, expressions, or skin tone
        - Body shape or proportions
        - Hair style or color
        - Visible body parts (arms, legs, neck)
        3. Maintain all hidden body parts correctly (e.g., legs under full-length skirts, torso under jackets)

        LIGHTING AND INTEGRATION:
        1. Adjust ONLY lighting and shadows to integrate the clothing naturally with the person
        2. Match the lighting direction, intensity, and color temperature from Image 1
        3. Add realistic shadows, wrinkles, and fabric draping that follow the person's body contours
        4. Ensure the clothing appears to naturally wrap around and fit the person's body shape

        NEGATIVE CONSTRAINTS (What to AVOID):
        - Adding clothing elements not present in Image 2 (extra pockets, buttons, patterns, trim, accessories)
        - Changing the clothing's original colors, patterns, or design
        - Modifying the person's body, face, or physical features
        - Creating unrealistic clothing layering (visible incompatible garments underneath)
        - Generating low-quality results with: blurry details, distorted proportions, unnatural lighting, poor fabric draping, floating garments, disconnected clothing parts, anatomical errors
        - Generating same Image in Image 1. With any conditions, try to put clothing item on the given Image 1 and generate new outfit.

        FINAL OUTPUT REQUIREMENTS:
        The result must appear as if the person from Image 1 is naturally wearing the exact clothing item from Image 2, with:
        - Photorealistic quality and proper integration
        - Correct clothing logic and layering
        - Preserved human features and proportions
        - Natural lighting and shadows
        - No modifications to the original clothing design
        """

        # Create parts list using Blob format (matching sample code)
        person_part = types.Part(
            inline_data=types.Blob(
                data=yourself_image_base64,
                mime_type="image/jpeg"
            )
        )
        clothing_part = types.Part(
            inline_data=types.Blob(
                data=clothing_image_base64,
                mime_type="image/jpeg"
            )
        )
        text_part = types.Part.from_text(text=main_prompt)

        # Contents is a list of Parts (not wrapped in Content object)
        contents = [person_part, clothing_part, text_part]

        # Configure safety settings - explicitly set to block medium and above for all harm categories
        safety_settings = [
            types.SafetySetting(
                category="HARM_CATEGORY_SEXUALLY_EXPLICIT",
                threshold="BLOCK_MEDIUM_AND_ABOVE"
            ),
            types.SafetySetting(
                category="HARM_CATEGORY_HATE_SPEECH",
                threshold="BLOCK_MEDIUM_AND_ABOVE"
            ),
            types.SafetySetting(
                category="HARM_CATEGORY_HARASSMENT",
                threshold="BLOCK_MEDIUM_AND_ABOVE"
            ),
            types.SafetySetting(
                category="HARM_CATEGORY_DANGEROUS_CONTENT",
                threshold="BLOCK_MEDIUM_AND_ABOVE"
            ),
        ]

        # Configure model response to include IMAGE output
        generate_config = types.GenerateContentConfig(
            response_modalities=["IMAGE"],
            temperature=0.2,
            safety_settings=safety_settings
        )

        # Send to model
        response = self.client.models.generate_content(
            model=self.model,
            contents=contents,
            config=generate_config,
        )

        # Check for content safety blocks
        if hasattr(response, 'prompt_feedback') and response.prompt_feedback:
            if hasattr(response.prompt_feedback, 'block_reason'):
                block_reason = str(response.prompt_feedback.block_reason)
                if 'PROHIBITED_CONTENT' in block_reason or 'SAFETY' in block_reason:
                    raise ValueError("CONTENT_SAFETY_VIOLATION: The uploaded images contain inappropriate or prohibited content that violates our safety policies.")

        # Extract the generated image
        if not response.candidates:
            raise RuntimeError("No image generated by model.")

        # Check if generation was blocked due to safety
        candidate = response.candidates[0]
        if hasattr(candidate, 'finish_reason'):
            finish_reason = str(candidate.finish_reason)
            if 'SAFETY' in finish_reason or 'PROHIBITED' in finish_reason:
                raise ValueError("CONTENT_SAFETY_VIOLATION: The generated content was blocked due to safety policy violations.")

        image_part = candidate.content.parts[0]
        return image_part.inline_data.data
