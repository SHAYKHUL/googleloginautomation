import csv
import time
from multiprocessing import Process
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def google_login(email, password):
    options = Options()
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--disable-infobars")
    options.add_argument("--disable-extensions")
    options.add_argument("--start-maximized")

    driver = webdriver.Chrome(service=Service(), options=options)
    wait = WebDriverWait(driver, 20)

    try:
        driver.get("https://accounts.google.com/signin")

        # Step 1: Enter email
        email_box = wait.until(EC.presence_of_element_located((By.ID, "identifierId")))
        email_box.clear()
        email_box.send_keys(email + Keys.RETURN)

        # Step 2: Enter password
        password_box = wait.until(EC.presence_of_element_located((By.NAME, "Passwd")))
        password_box.clear()
        password_box.send_keys(password + Keys.RETURN)

        # Step 3: Wait until account loads
        wait.until(EC.url_contains("myaccount.google.com"))
        driver.get("https://myaccount.google.com/")

        print(f"✅ Logged in: {email}")

        # Step 4: Go to 2FA page
        driver.get("https://myaccount.google.com/signinoptions/twosv")
        # Step 5: Click the 'Turn on 2FA' button using provided XPath
        try:
            twofa_btn = wait.until(EC.element_to_be_clickable((By.XPATH, '//*[@id="yDmH0d"]/c-wiz/div/div[2]/div[2]/c-wiz/div/div[1]/div[4]/div[2]/div/div/div/button/span[4]')))
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", twofa_btn)
            time.sleep(1)
            try:
                twofa_btn.click()
            except Exception:
                driver.execute_script("arguments[0].click();", twofa_btn)
        except Exception as e:
            print(f"❌ Could not find 2FA button: {e}")
            driver.quit()
            return

        # Step 6: Wait for 'Add a phone number' modal and input a random phone number
        try:
            time.sleep(2)  # Allow modal animation to finish
            phone_input = wait.until(EC.visibility_of_element_located((By.XPATH, '//input[@type="tel"]')))
            import random
            area_codes = [212, 213, 312, 415, 516, 617, 718, 805, 818, 917, 202, 305, 404, 512, 602, 703, 801, 858, 954]
            area = str(random.choice(area_codes))
            prefix = str(random.randint(200, 999))
            line = str(random.randint(1000, 9999))
            phone_number = f"({area}) {prefix}-{line}"
            phone_input.clear()
            phone_input.send_keys(phone_number)

            # Click 'Next' button in modal using span jsname and text
            next_btn = wait.until(EC.element_to_be_clickable((By.XPATH, '//button[.//span[@jsname="V67aGc" and text()="Next"]]')))
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", next_btn)
            time.sleep(1)
            try:
                next_btn.click()
            except Exception:
                driver.execute_script("arguments[0].click();", next_btn)
            print(f"✅ 2FA process started for {email} with phone {phone_number}")

            # After entering phone number, wait for and click Save button if present
            try:
                save_btn = wait.until(EC.element_to_be_clickable((By.XPATH, '//*[@id="yDmH0d"]/div[12]/div[2]/div/div[2]/div[4]/button/span[5]')))
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", save_btn)
                time.sleep(1)
                try:
                    save_btn.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", save_btn)
                print("✅ Save button clicked to confirm phone number.")
            except Exception as e:
                print(f"❌ Save button not found or not clickable: {e}")

            # After Save, click Done button in final modal if present
            try:
                done_btn = wait.until(EC.element_to_be_clickable((By.XPATH, '//button[.//span[@jsname="V67aGc" and text()="Done"]]')))
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", done_btn)
                time.sleep(1)
                try:
                    done_btn.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", done_btn)
                print("✅ Done button clicked to finish 2FA setup.")
            except Exception as e:
                print(f"❌ Done button not found or not clickable: {e}")

            # Step 7: Go to app passwords page and create an app password
            try:
                driver.get("https://myaccount.google.com/apppasswords")
                time.sleep(2)
                app_input = wait.until(EC.visibility_of_element_located((By.XPATH, '//input[@id="i4" and @jsname="YPqjbf"]')))
                app_input.clear()
                app_input.send_keys("AutomationApp")

                create_btn = wait.until(EC.element_to_be_clickable((By.XPATH, '//button[.//span[@jsname="V67aGc" and text()="Create"]]')))
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", create_btn)
                time.sleep(1)
                try:
                    create_btn.click()
                except Exception:
                    driver.execute_script("arguments[0].click();", create_btn)
                print("✅ App password created.")

                # Step 8: Collect the generated app password from the modal
                try:
                    modal = wait.until(EC.visibility_of_element_located((By.XPATH, '//div[@class="uW2Fw-P5QLlc" and @aria-modal="true"]')))
                    strong = modal.find_element(By.XPATH, './/strong[@class="v2CTKd KaSAf"]')
                    spans = strong.find_elements(By.TAG_NAME, 'span')
                    app_password = ''.join([span.text for span in spans]).replace(' ', '')
                    print(f"🔑 Generated app password: {app_password}")
                except Exception as e:
                    print(f"❌ Could not extract app password: {e}")

            except Exception as e:
                print(f"❌ App password creation failed: {e}")

            # Keep browser alive
            while True:
                time.sleep(60)
        except Exception as e:
            print(f"❌ 2FA phone modal failed: {e}")
            try:
                inputs = driver.find_elements(By.TAG_NAME, 'input')
                print(f"Found {len(inputs)} input fields:")
                for inp in inputs:
                    print(f"Type: {inp.get_attribute('type')}, Name: {inp.get_attribute('name')}, Value: {inp.get_attribute('value')}")
            except Exception as debug_e:
                print(f"Debug failed: {debug_e}")
            print("Browser will remain open for manual correction.")
            while True:
                time.sleep(60)

    except Exception as e:
        print(f"❌ Login failed for {email}: {e}")
        driver.quit()

if __name__ == "__main__":
    processes = []
    with open("accounts.csv", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            email = row["email"].strip()
            password = row["password"].strip()
            p = Process(target=google_login, args=(email, password))
            p.start()
            processes.append(p)
    print("🔥 All login processes started. Browsers should be open.")
    for p in processes:
        p.join()
