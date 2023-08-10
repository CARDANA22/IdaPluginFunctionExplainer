import idaapi
import idautils
import time
import requests

class MyIDAPlugin(idaapi.plugin_t):
    flags = 0
    comment = "This is a plugin to comment out functions and enhance readability."
    help = "No help available."
    wanted_name = "Function Explainer"
    wanted_hotkey = "Alt-F8" 

    def init(self):
        idaapi.msg("\n\n\n\n\n\nPlugin initialized.\n")
        return idaapi.PLUGIN_KEEP  

    def run(self, arg):
        idaapi.msg("Plugin activated.\n")
        
        pseudocode = self.extract_pseudocode()
        commented_code = self.send_to_llm(pseudocode)
        self.display_in_ida(commented_code)

    def extract_pseudocode(self):
        idaapi.msg("Extracting pseudocode.\n")

        # Ensure Hex-Rays Decompiler is available
        if not idaapi.init_hexrays_plugin():
            idaapi.msg("Hex-Rays Decompiler is not available!\n")
            return None

        all_pseudocode = []

        # Iterate over all functions in the IDB
        i = 0
        for function_ea in idautils.Functions():
            f = idaapi.get_func(function_ea)
            if not f:
                continue

            # Decompile the function
            cfunc = idaapi.decompile(f)
            if not cfunc:
                idaapi.msg(f"Failed to decompile function at {function_ea:x}\n")
                continue
            i = i +1
            # Get the pseudocode as plain text
            pseudocode_lines = [line.line for line in cfunc.get_pseudocode()]
            pseudocode_text = "\n".join(pseudocode_lines)
            all_pseudocode.append(pseudocode_text)

        idaapi.msg(f"Total Functions: {str(i)} \n")
        return all_pseudocode

    def send_to_llm(self, pseudocode_list):
        idaapi.msg("Sending to LLM.\n")

        start_time = []
        end_time = []

        token_limit = 16000
        
        OPENAI_API_ENDPOINT = "https://api.openai.com//v1/chat/completions"
        HEADERS = {
            "Authorization": "Bearer sk-placeholder",
            "Content-Type": "application/json"
        }

        # Limit to the first 5 functions for testing
        #pseudocode_list = pseudocode_list[:5]

        functions_left = len(pseudocode_list)

        # Calculate total tokens for all pseudocode
        total_tokens = sum([len(pseudocode.split()) for pseudocode in pseudocode_list]) + 59
        idaapi.msg(f"Total tokens calculated: {total_tokens}\n")

        # Determine how many requests can be send per minute without exceeding the TPM limit
        all_commented_code = []

        for pseudocode in pseudocode_list:
            if not pseudocode:  # Check if pseudocode is empty
                continue

            idaapi.msg("\n\n\nSending request...\n")

            chunks = self.split_into_chunks(pseudocode, token_limit)

            start_time.append(time.time())

            for chunk in chunks:
                idaapi.msg(f"\nChunk size: {len(chunk.split())} tokens\n")

                DATA = {
                    "model": "gpt-3.5-turbo-16k",
                    "messages": [
                        {"role": "system", "content": "You are an expert coder and only respond with code"},
                        {"role": "user", "content": f"Analyze the following pseudocode and provide a concise comment that describes its general purpose: {chunk}. Also,  If their are variables suggest names to make the code more readable like this:   Olad Name = new Name \n The new Name is the name you suggested it. If no variables are provided, skip that"}
                    ],
                    "max_tokens": len(chunk.split()) + 100,  # Adjust as needed to account for comments
                    "temperature": 0.7
                }
                
                response = requests.post(OPENAI_API_ENDPOINT, headers=HEADERS, json=DATA)
                response_data = response.json()

                #idaapi.msg(f"X-RateLimit-Remaining: {response.headers.get('x-ratelimit-remaining-requests')}\n")
                #idaapi.msg(f"X-RateLimit-Reset: {response.headers.get('x-ratelimit-reset-requests')}\n")
               
                remaining_requests = int(response.headers.get('x-ratelimit-remaining-requests', 0))
                reset_time_str = (response.headers.get('x-ratelimit-reset-requests', 0))
                reset_time_ms = int(reset_time_str.rstrip(' ms'))

                if remaining_requests <= 0:
                    wait_time = reset_time_ms / 1000.0  # Convert to seconds
                    idaapi.msg(f"Rate limit exceeded. Waiting for {wait_time} seconds before next request...\n")
                    time.sleep(wait_time)

                if 'error' in response_data:
                    idaapi.msg(f"OpenAI API Error: {response_data['error']['message']}\n")
                    # Set a default comment indicating the error
                    return [f"OpenAI API Error: {response_data['error']['message']}"]

                # Extract the commented code from the response
                commented_code = response_data.get("choices", [{}])[0].get("message", {}).get("content", "")
                idaapi.msg(f"Extracted commented code from API response:\n{commented_code}\n")
                all_commented_code.append(commented_code)

            
            end_time.append(time.time())
            tTime = 0

            for i1, i2 in zip(end_time, start_time):
                tTime = tTime + (i1 - i2)

            avaerage_tim = tTime / len(end_time)
            idaapi.msg(f"API request took {tTime:.2f} seconds.\n")

            functions_left -= 1

            estimated_total_time = avaerage_tim  * functions_left
            idaapi.msg(f"Estimated total time for all requests left: {estimated_total_time:.2f} seconds. Or {(estimated_total_time/60):.2f} minutes\n")

            idaapi.msg(f"{functions_left} Functions left\n")

        idaapi.msg("All requests sent.\n")
        return all_commented_code

    def split_into_chunks(self, text, max_tokens):
        # This function will split the text into smaller chunks, each with a maximum of 'max_tokens'
        words = text.split()
        chunks = []
        current_chunk = []

        current_token_count = 0
        for word in words:
            if current_token_count + len(word) > max_tokens:
                chunks.append(" ".join(current_chunk))
                current_chunk = []
                current_token_count = 0

            current_chunk.append(word)
            current_token_count += len(word)

        if current_chunk:
            chunks.append(" ".join(current_chunk))

        return chunks

    def display_in_ida(self, commented_code_list):
        idaapi.msg("Displaying in IDA.\n")

        # Convert the generator to a list
        functions_list = list(idautils.Functions())

        last_function_ea = None  

        for idx, commented_code in enumerate(commented_code_list):
            
            if idx >= len(functions_list):
                idaapi.msg("Number of commented codes exceeds the number of functions. Exiting loop.\n")
                break

            # Get the function's start address
            function_ea = functions_list[idx]

            # Get the func_t object for the function
            func = idaapi.get_func(function_ea)
            if not func:
                idaapi.msg(f"Failed to get func_t object for function at address {function_ea:x}\n")
                continue


            idaapi.msg(f"Setting comment for function at {function_ea:x}: \n{commented_code}\n")
            idaapi.set_func_cmt(func, commented_code, True)

            last_function_ea = function_ea

        idaapi.msg("All functions commented.\n")

        # If we have a valid last function address, jump to it
        if last_function_ea:
            idaapi.jumpto(last_function_ea)

    def term(self):
        idaapi.msg("Plugin terminated.\n")


def PLUGIN_ENTRY():
    return MyIDAPlugin()
