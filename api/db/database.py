from psycopg2 import pool, DatabaseError
import base64
import calendar
import threading
from datetime import datetime
from configparser import ConfigParser


class Database:
    _pool = None
    _lock = threading.Lock()

    @classmethod
    def _get_pool(cls):
        """Initialize connection pool once, thread-safe"""
        if cls._pool is None:
            with cls._lock:
                if cls._pool is None:  # Double-check after acquiring lock
                    config = cls._config()
                    cls._pool = pool.SimpleConnectionPool(
                        minconn=1,      # Minimum connections to keep open
                        maxconn=10,     # Maximum connections (10 concurrent users)
                        connect_timeout=5,  # 5 seconds to establish connection
                        options='-c statement_timeout=30000',  # 30 seconds max query time
                        **config
                    )
        return cls._pool

    def __enter__(self):
        self.conn = self._get_pool().getconn()
        self.cursor = self.conn.cursor()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, "cursor") and self.cursor:
            self.cursor.close()
        if hasattr(self, "conn") and self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            # Return connection to pool instead of closing
            self._get_pool().putconn(self.conn)

    @staticmethod
    def _config(filename="api/db/database.ini", section="postgresql"):
        parser = ConfigParser()
        parser.read(filename)
        db_config = {}
        if parser.has_section(section):
            for key, value in parser.items(section):
                db_config[key] = value
        else:
            raise Exception(f"Section {section} not found in {filename}")
        return db_config
    
    def get_user_info(
            self,
            user_id
        ):
        query = """
            SELECT user_name, user_surname, user_email, picture_url, user_type,
                   storage_left, designs_left, last_payment_at, nsfw_violations,
                   subscription_status, subscription_ends_at, user_status
            FROM users
            WHERE user_id = %s
        """
        try:
            self.cursor.execute(query, (user_id,))
            result = self.cursor.fetchone()

            if result:
                last_payment = result[7]
                next_renewal = None
                subscription_status = result[9] or 'none'
                subscription_ends_at = result[10]

                # Calculate next renewal date if premium and has last_payment_at
                if last_payment and result[4] == 'premium':
                    # Add exactly 1 month (handles month-end edge cases properly)
                    year = last_payment.year
                    month = last_payment.month
                    day = last_payment.day

                    # Increment month
                    if month == 12:
                        month = 1
                        year += 1
                    else:
                        month += 1

                    # Handle day overflow (e.g., Jan 31 -> Feb 28/29)
                    max_day = calendar.monthrange(year, month)[1]
                    day = min(day, max_day)

                    next_renewal_date = last_payment.replace(year=year, month=month, day=day)
                    next_renewal = next_renewal_date.strftime("%b %d, %Y")

                # Calculate days for cancelled/expired subscriptions
                days_until_expiry = None
                days_since_expiry = None
                now = datetime.now()

                if subscription_status == 'cancelled' and subscription_ends_at:
                    delta = subscription_ends_at - now
                    days_until_expiry = max(0, delta.days)
                elif subscription_status == 'expired' and subscription_ends_at:
                    delta = now - subscription_ends_at
                    days_since_expiry = max(0, delta.days)

                return {
                    "name": result[0],
                    "surname": result[1],
                    "email": result[2],
                    "picture_url": result[3],
                    "type": result[4],
                    "storage_left": result[5],
                    "designs_left": result[6],
                    "next_renewal_date": next_renewal,
                    "nsfw_violations": result[8],
                    "subscription_status": subscription_status,
                    "subscription_ends_at": subscription_ends_at.isoformat() if subscription_ends_at else None,
                    "days_until_expiry": days_until_expiry,
                    "days_since_expiry": days_since_expiry,
                    "user_status": result[11]
                }
            return None

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e
    
    def insert_image(
            self,
            user_id,
            category,
            image_bytes,
            preview_bytes
        ):
        # Check if user has storage space (FOR UPDATE locks row to prevent race condition)
        credit_check_query = """
        SELECT storage_left FROM users WHERE user_id = %s FOR UPDATE
        """

        insert_query = """
        INSERT INTO images (user_id, category, image_bytes, preview_bytes)
        VALUES (%s, %s, %s, %s)
        RETURNING image_id, created_at
        """

        decrement_query = """
        UPDATE users SET storage_left = storage_left - 1
        WHERE user_id = %s
        RETURNING storage_left
        """

        try:
            self.cursor.execute(credit_check_query, (user_id,))
            credit_result = self.cursor.fetchone()

            if not credit_result or credit_result[0] <= 0:
                raise Exception("Insufficient storage space")

            self.cursor.execute(insert_query, (
                user_id,
                category,
                image_bytes,
                preview_bytes
            ))
            result = self.cursor.fetchone()
            image_id = result[0]
            created_at = result[1]

            self.cursor.execute(decrement_query, (user_id,))
            new_storage = self.cursor.fetchone()[0]

            return {
                "image_id": str(image_id),
                "preview_base64": base64.b64encode(preview_bytes).decode('utf8'),
                "created_at": created_at.isoformat(),
                "storage_left": new_storage
            }
        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e
    
    def insert_designed_image(
            self,
            user_id,
            yourself_image_id,
            clothing_image_id,
            designed_image_bytes,
            designed_preview_bytes
        ):
        # FOR UPDATE locks row to prevent race condition on credits
        credit_check_query = """
        SELECT designs_left, storage_left FROM users WHERE user_id = %s FOR UPDATE
        """

        insert_query = """
        INSERT INTO designs (user_id, yourself_image_id, clothing_image_id, image_bytes, preview_bytes)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING image_id, created_at
        """

        decrement_query = """
        UPDATE users SET designs_left = designs_left - 1, storage_left = storage_left - 1
        WHERE user_id = %s
        RETURNING designs_left, storage_left
        """

        try:
            self.cursor.execute(credit_check_query, (user_id,))
            credit_result = self.cursor.fetchone()

            if not credit_result or credit_result[0] <= 0:
                raise Exception("Insufficient design credits")

            if credit_result[1] <= 0:
                raise Exception("Insufficient storage space")

            self.cursor.execute(insert_query, (
                user_id,
                yourself_image_id,
                clothing_image_id,
                designed_image_bytes,
                designed_preview_bytes
            ))
            result = self.cursor.fetchone()
            image_id = result[0]
            created_at = result[1]

            self.cursor.execute(decrement_query, (user_id,))
            new_credits = self.cursor.fetchone()

            return {
                "image_id": str(image_id),
                "preview_base64": base64.b64encode(designed_preview_bytes).decode('utf8'),
                "created_at": created_at.isoformat(),
                "designs_left": new_credits[0],
                "storage_left": new_credits[1]
            }
        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e
    
    def get_preview_images(
            self,
            user_id
        ):
        query = """
        SELECT image_id, category, preview_bytes, faved, created_at
        FROM images
        WHERE user_id = %s
        ORDER BY created_at DESC
        """
        try:
            self.cursor.execute(query, (user_id,))
            data = self.cursor.fetchall()

            if not data:
                return {}

            result = {"yourself": [], "clothing": []}
            for row in data:
                category = row[1]
                result[category].append({
                    "id": str(row[0]),
                    "base64": base64.b64encode(row[2]).decode('utf-8'),
                    "faved": row[3],
                    "created_at": row[4].isoformat()
                })
            return result

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e
    
    def get_preview_designs(
            self,
            user_id
        ):
        query = """
        SELECT image_id, preview_bytes, faved, created_at
        FROM designs
        WHERE user_id = %s
        ORDER BY created_at DESC
        """
        try:
            self.cursor.execute(query, (user_id,))
            data = self.cursor.fetchall()

            if not data:
                return []
            
            result = []
            for row in data:
                result.append({
                    "id": str(row[0]),
                    "base64": base64.b64encode(row[1]).decode('utf-8'),
                    "faved": row[2],
                    "created_at": row[3].isoformat()
                })
            return result
            
        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e
        
    def get_image(
            self,
            user_id,
            image_id
        ):
        query = """
        SELECT image_bytes
        FROM images
        WHERE user_id = %s AND image_id = %s
        """
        try:
            self.cursor.execute(query, (user_id, image_id))
            data = self.cursor.fetchone()

            if not data:
                return None

            return data[0]

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def get_design(
            self,
            user_id,
            image_id
        ):
        query = """
        SELECT image_bytes
        FROM designs
        WHERE user_id = %s AND image_id = %s
        """
        try:
            self.cursor.execute(query, (user_id, image_id))
            data = self.cursor.fetchone()

            if not data:
                return None

            return data[0]

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def delete_image(
            self,
            user_id,
            image_id
        ):
        delete_query = """
        DELETE FROM images
        WHERE image_id = %s AND user_id = %s
        """

        increment_query = """
        UPDATE users SET storage_left = storage_left + 1
        WHERE user_id = %s
        RETURNING storage_left
        """

        try:
            self.cursor.execute(delete_query, (image_id, user_id))
            if self.cursor.rowcount == 0:
                return None

            self.cursor.execute(increment_query, (user_id,))
            result = self.cursor.fetchone()

            return {"storage_left": result[0]}

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e
    
    def delete_design(
            self,
            user_id,
            image_id
        ):
        delete_query = """
        DELETE FROM designs
        WHERE image_id = %s AND user_id = %s
        """

        increment_query = """
        UPDATE users SET storage_left = storage_left + 1
        WHERE user_id = %s
        RETURNING storage_left
        """

        try:
            self.cursor.execute(delete_query, (image_id, user_id))
            if self.cursor.rowcount == 0:
                return None

            self.cursor.execute(increment_query, (user_id,))
            result = self.cursor.fetchone()
            return {"storage_left": result[0]}
        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e
    
    def update_design_fav(
            self,
            user_id,
            image_id
        ):
        query = """
        UPDATE designs
        SET faved = NOT faved
        WHERE image_id = %s AND user_id = %s
        RETURNING faved
        """
        try:
            self.cursor.execute(query, (image_id, user_id))
            result = self.cursor.fetchone()

            if not result:
                return False

            return True
        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def update_image_fav(
            self,
            user_id,
            image_id
        ):
        query = """
        UPDATE images
        SET faved = NOT faved
        WHERE image_id = %s AND user_id = %s
        RETURNING faved
        """
        try:
            self.cursor.execute(query, (image_id, user_id))
            result = self.cursor.fetchone()

            if not result:
                return False

            return True
        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def insert_feedback(
            self,
            user_id,
            message
        ):

        count_query = """
        SELECT COUNT(*) FROM feedbacks WHERE user_id = %s
        """

        insert_query = """
        INSERT INTO feedbacks (user_id, message)
        VALUES (%s, %s)
        RETURNING feedback_id, created_at
        """

        try:
            self.cursor.execute(count_query, (user_id,))
            count_result = self.cursor.fetchone()

            if count_result and count_result[0] >= 5:
                raise Exception("Feedback limit reached!")

            self.cursor.execute(insert_query, (user_id, message))
            result = self.cursor.fetchone()
            feedback_id = result[0]
            created_at = result[1]

            return {
                "feedback_id": str(feedback_id),
                "created_at": created_at.isoformat()
            }
        
        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def get_user_by_email(self, email):
        query = """
        SELECT user_id
        FROM users
        WHERE user_email = %s
        """
        try:
            self.cursor.execute(query, (email,))
            result = self.cursor.fetchone()

            if result:
                return {
                    "user_id": str(result[0])
                }
            return None

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def create_google_user(self, email, name, surname, picture_url, google_id):
        insert_query = """
        INSERT INTO users (user_name, user_surname, user_email, google_id, picture_url)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING user_id
        """

        try:
            self.cursor.execute(insert_query, (
                name or "",
                surname or "",
                email,
                google_id,
                picture_url or ""
            ))
            result = self.cursor.fetchone()
            user_id = str(result[0])
            return user_id

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def increment_nsfw_violation(self, user_id):
        """
        Increment NSFW violation counter for a user.
        Returns the new violation count.
        """
        query = """
            UPDATE users
            SET nsfw_violations = nsfw_violations + 1
            WHERE user_id = %s
            RETURNING nsfw_violations
        """
        try:
            self.cursor.execute(query, (user_id,))
            result = self.cursor.fetchone()

            if result:
                return result[0]
            return None

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def get_nsfw_violations(self, user_id):
        """
        Get the current NSFW violation count for a user.
        """
        query = """
            SELECT nsfw_violations
            FROM users
            WHERE user_id = %s
        """
        try:
            self.cursor.execute(query, (user_id,))
            result = self.cursor.fetchone()

            if result:
                return result[0]
            return 0

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def reset_nsfw_violations(self, user_id):
        """
        Reset NSFW violation counter to 0 for a user.
        Used for appeals or administrative corrections.
        """
        query = """
            UPDATE users
            SET nsfw_violations = 0
            WHERE user_id = %s
            RETURNING nsfw_violations
        """
        try:
            self.cursor.execute(query, (user_id,))
            result = self.cursor.fetchone()

            if result:
                return True
            return False

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e
    
    def create_subscription(
            self,
            user_email,
            customer_id,
            receipt_url,
            subscription_id=None
        ):
        query = """
        UPDATE users
        SET user_type = 'premium',
            storage_left = 100,
            designs_left = 50,
            last_payment_at = CURRENT_TIMESTAMP,
            lemon_squeezy_customer_id = %s,
            receipt_url = %s,
            subscription_status = 'active',
            subscription_id = %s,
            subscription_ends_at = NULL
        WHERE user_email = %s
        RETURNING user_id, user_name, user_surname
        """
        try:
            self.cursor.execute(query, (customer_id, receipt_url, subscription_id, user_email))
            result = self.cursor.fetchone()

            if not result:
                raise Exception(f"User with email {user_email} not found")

            return {
                "user_id": str(result[0]),
                "user_name": result[1],
                "user_surname": result[2],
                "user_type": "premium",
                "subscription_status": "active",
                "storage_left": 100,
                "designs_left": 50
            }

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def cancel_subscription(self, customer_id, user_email, subscription_id, ends_at):
        """
        Cancel subscription with robust user lookup.
        Primary: lookup by lemon_squeezy_customer_id
        Fallback: lookup by user_email

        If ends_at is None, calculates from last_payment_at + 1 month.
        """
        # First try to find user by customer_id, then fallback to email
        find_user_query = """
            SELECT user_id, last_payment_at
            FROM users
            WHERE lemon_squeezy_customer_id = %s
        """

        try:
            self.cursor.execute(find_user_query, (str(customer_id),))
            user_result = self.cursor.fetchone()

            # Fallback to email if customer_id not found
            if not user_result and user_email:
                find_by_email_query = """
                    SELECT user_id, last_payment_at
                    FROM users
                    WHERE user_email = %s
                """
                self.cursor.execute(find_by_email_query, (user_email,))
                user_result = self.cursor.fetchone()

            if not user_result:
                raise Exception(f"User not found with customer_id {customer_id} or email {user_email}")

            user_id = user_result[0]
            last_payment_at = user_result[1]

            # Calculate ends_at if not provided
            final_ends_at = ends_at
            if not final_ends_at and last_payment_at:
                # Calculate last_payment_at + 1 month
                year = last_payment_at.year
                month = last_payment_at.month
                day = last_payment_at.day

                if month == 12:
                    month = 1
                    year += 1
                else:
                    month += 1

                max_day = calendar.monthrange(year, month)[1]
                day = min(day, max_day)
                final_ends_at = last_payment_at.replace(year=year, month=month, day=day)

            # Update the subscription status
            update_query = """
                UPDATE users
                SET subscription_status = 'cancelled',
                    subscription_id = %s,
                    subscription_ends_at = %s
                WHERE user_id = %s
                RETURNING user_id, user_name, user_surname, subscription_ends_at
            """
            self.cursor.execute(update_query, (subscription_id, final_ends_at, user_id))
            result = self.cursor.fetchone()

            if not result:
                raise Exception(f"Failed to update user {user_id}")

            return {
                "user_id": str(result[0]),
                "user_name": result[1],
                "user_surname": result[2],
                "subscription_status": "cancelled",
                "subscription_ends_at": result[3].isoformat() if result[3] else None
            }

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def resume_subscription(self, customer_id, user_email, subscription_id):
        """
        Resume a cancelled subscription.
        Uses same robust lookup as cancel_subscription.
        Sets subscription_status back to 'active' and clears ends_at.
        Does NOT reset credits (user never lost them).
        """
        find_user_query = """
            SELECT user_id
            FROM users
            WHERE lemon_squeezy_customer_id = %s
        """

        try:
            self.cursor.execute(find_user_query, (str(customer_id),))
            user_result = self.cursor.fetchone()

            if not user_result and user_email:
                find_by_email_query = """
                    SELECT user_id
                    FROM users
                    WHERE user_email = %s
                """
                self.cursor.execute(find_by_email_query, (user_email,))
                user_result = self.cursor.fetchone()

            if not user_result:
                raise Exception(f"User not found with customer_id {customer_id} or email {user_email}")

            user_id = user_result[0]

            update_query = """
                UPDATE users
                SET subscription_status = 'active',
                    subscription_id = %s,
                    subscription_ends_at = NULL
                WHERE user_id = %s
                RETURNING user_id, user_name, user_surname
            """
            self.cursor.execute(update_query, (subscription_id, user_id))
            result = self.cursor.fetchone()

            if not result:
                raise Exception(f"Failed to update user {user_id}")

            return {
                "user_id": str(result[0]),
                "user_name": result[1],
                "user_surname": result[2],
                "subscription_status": "active"
            }

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def expire_subscription(self, customer_id, user_email, subscription_id):
        """
        Mark subscription as expired.
        Uses same robust lookup as other subscription functions.
        Sets subscription_status to 'expired'.
        Preserves subscription_ends_at for calculating days since expiry.
        Does NOT change user_type or delete data.
        """
        find_user_query = """
            SELECT user_id
            FROM users
            WHERE lemon_squeezy_customer_id = %s
        """

        try:
            self.cursor.execute(find_user_query, (str(customer_id),))
            user_result = self.cursor.fetchone()

            if not user_result and user_email:
                find_by_email_query = """
                    SELECT user_id
                    FROM users
                    WHERE user_email = %s
                """
                self.cursor.execute(find_by_email_query, (user_email,))
                user_result = self.cursor.fetchone()

            if not user_result:
                raise Exception(f"User not found with customer_id {customer_id} or email {user_email}")

            user_id = user_result[0]

            update_query = """
                UPDATE users
                SET subscription_status = 'expired',
                    subscription_id = %s
                WHERE user_id = %s
                RETURNING user_id, user_name, user_surname, subscription_ends_at
            """
            self.cursor.execute(update_query, (subscription_id, user_id))
            result = self.cursor.fetchone()

            if not result:
                raise Exception(f"Failed to update user {user_id}")

            return {
                "user_id": str(result[0]),
                "user_name": result[1],
                "user_surname": result[2],
                "subscription_status": "expired",
                "subscription_ends_at": result[3].isoformat() if result[3] else None
            }

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def renew_subscription(self, customer_id, user_email, subscription_id):
        """
        Handle monthly subscription renewal (payment success).
        Resets designs_left to 50 (monthly quota).
        Updates last_payment_at to current timestamp.
        Does NOT reset storage_left (cumulative).
        Uses same robust lookup as other subscription functions.
        """
        find_user_query = """
            SELECT user_id
            FROM users
            WHERE lemon_squeezy_customer_id = %s
        """

        try:
            self.cursor.execute(find_user_query, (str(customer_id),))
            user_result = self.cursor.fetchone()

            if not user_result and user_email:
                find_by_email_query = """
                    SELECT user_id
                    FROM users
                    WHERE user_email = %s
                """
                self.cursor.execute(find_by_email_query, (user_email,))
                user_result = self.cursor.fetchone()

            if not user_result:
                raise Exception(f"User not found with customer_id {customer_id} or email {user_email}")

            user_id = user_result[0]

            update_query = """
                UPDATE users
                SET designs_left = 50,
                    last_payment_at = CURRENT_TIMESTAMP,
                    subscription_status = 'active',
                    subscription_id = %s,
                    subscription_ends_at = NULL
                WHERE user_id = %s
                RETURNING user_id, user_name, user_surname, designs_left, storage_left
            """
            self.cursor.execute(update_query, (subscription_id, user_id))
            result = self.cursor.fetchone()

            if not result:
                raise Exception(f"Failed to update user {user_id}")

            return {
                "user_id": str(result[0]),
                "user_name": result[1],
                "user_surname": result[2],
                "subscription_status": "active",
                "designs_left": result[3],
                "storage_left": result[4]
            }

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def fail_subscription_payment(self, customer_id, user_email, subscription_id):
        """
        Handle payment failure - mark as past_due.
        User still has access while Lemon Squeezy retries.
        Uses same robust lookup as other subscription functions.
        """
        find_user_query = """
            SELECT user_id
            FROM users
            WHERE lemon_squeezy_customer_id = %s
        """

        try:
            self.cursor.execute(find_user_query, (str(customer_id),))
            user_result = self.cursor.fetchone()

            if not user_result and user_email:
                find_by_email_query = """
                    SELECT user_id
                    FROM users
                    WHERE user_email = %s
                """
                self.cursor.execute(find_by_email_query, (user_email,))
                user_result = self.cursor.fetchone()

            if not user_result:
                raise Exception(f"User not found with customer_id {customer_id} or email {user_email}")

            user_id = user_result[0]

            update_query = """
                UPDATE users
                SET subscription_status = 'past_due',
                    subscription_id = %s
                WHERE user_id = %s
                RETURNING user_id, user_name, user_surname
            """
            self.cursor.execute(update_query, (subscription_id, user_id))
            result = self.cursor.fetchone()

            if not result:
                raise Exception(f"Failed to update user {user_id}")

            return {
                "user_id": str(result[0]),
                "user_name": result[1],
                "user_surname": result[2],
                "subscription_status": "past_due"
            }

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def recover_subscription(self, customer_id, user_email, subscription_id):
        """
        Handle payment recovery after failed payment.
        Sets subscription_status back to 'active'.
        Uses same robust lookup as other subscription functions.
        """
        find_user_query = """
            SELECT user_id
            FROM users
            WHERE lemon_squeezy_customer_id = %s
        """

        try:
            self.cursor.execute(find_user_query, (str(customer_id),))
            user_result = self.cursor.fetchone()

            if not user_result and user_email:
                find_by_email_query = """
                    SELECT user_id
                    FROM users
                    WHERE user_email = %s
                """
                self.cursor.execute(find_by_email_query, (user_email,))
                user_result = self.cursor.fetchone()

            if not user_result:
                raise Exception(f"User not found with customer_id {customer_id} or email {user_email}")

            user_id = user_result[0]

            update_query = """
                UPDATE users
                SET subscription_status = 'active',
                    subscription_id = %s
                WHERE user_id = %s
                RETURNING user_id, user_name, user_surname
            """
            self.cursor.execute(update_query, (subscription_id, user_id))
            result = self.cursor.fetchone()

            if not result:
                raise Exception(f"Failed to update user {user_id}")

            return {
                "user_id": str(result[0]),
                "user_name": result[1],
                "user_surname": result[2],
                "subscription_status": "active"
            }

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def refund_subscription(self, customer_id, user_email, subscription_id):
        """
        Handle subscription refund.
        Sets subscription_status to 'refunded'.
        User loses access immediately but data preserved.
        Uses same robust lookup as other subscription functions.
        """
        find_user_query = """
            SELECT user_id
            FROM users
            WHERE lemon_squeezy_customer_id = %s
        """

        try:
            self.cursor.execute(find_user_query, (str(customer_id),))
            user_result = self.cursor.fetchone()

            if not user_result and user_email:
                find_by_email_query = """
                    SELECT user_id
                    FROM users
                    WHERE user_email = %s
                """
                self.cursor.execute(find_by_email_query, (user_email,))
                user_result = self.cursor.fetchone()

            if not user_result:
                raise Exception(f"User not found with customer_id {customer_id} or email {user_email}")

            user_id = user_result[0]

            update_query = """
                UPDATE users
                SET subscription_status = 'refunded',
                    subscription_id = %s
                WHERE user_id = %s
                RETURNING user_id, user_name, user_surname
            """
            self.cursor.execute(update_query, (subscription_id, user_id))
            result = self.cursor.fetchone()

            if not result:
                raise Exception(f"Failed to update user {user_id}")

            return {
                "user_id": str(result[0]),
                "user_name": result[1],
                "user_surname": result[2],
                "subscription_status": "refunded"
            }

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def get_user_subscription_id(self, user_id):
        """
        Get user's subscription_id for Lemon Squeezy API calls.
        Only returns if the subscription is active.
        """
        query = """
            SELECT subscription_id, subscription_status
            FROM users
            WHERE user_id = %s
        """
        try:
            self.cursor.execute(query, (user_id,))
            result = self.cursor.fetchone()

            if not result:
                return None

            subscription_id = result[0]
            subscription_status = result[1]

            # Only return if subscription is active
            if subscription_status != 'active':
                return None

            return {
                "subscription_id": subscription_id,
                "subscription_status": subscription_status
            }

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def get_user_subscription_for_resume(self, user_id):
        """
        Get user's subscription_id for resuming a cancelled subscription.
        Only returns if the subscription status is 'cancelled'.
        """
        query = """
            SELECT subscription_id, subscription_status
            FROM users
            WHERE user_id = %s
        """
        try:
            self.cursor.execute(query, (user_id,))
            result = self.cursor.fetchone()

            if not result:
                return None

            subscription_id = result[0]
            subscription_status = result[1]

            # Only return if subscription is cancelled (can be resumed)
            if subscription_status != 'cancelled':
                return None

            return {
                "subscription_id": subscription_id,
                "subscription_status": subscription_status
            }

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def store_cancellation_reason(self, user_id, reason):
        """
        Store cancellation reason in the feedbacks table.
        Useful for analytics on why users cancel.
        """
        insert_query = """
            INSERT INTO feedbacks (user_id, message, feedback_type)
            VALUES (%s, %s, 'cancellation')
            RETURNING feedback_id, created_at
        """
        try:
            # Try with feedback_type column first
            self.cursor.execute(insert_query, (user_id, f"Cancellation reason: {reason}"))
            result = self.cursor.fetchone()
            return {
                "feedback_id": str(result[0]),
                "created_at": result[1].isoformat()
            }
        except Exception:
            # Fallback: use simple insert without feedback_type column
            self.conn.rollback()
            fallback_query = """
                INSERT INTO feedbacks (user_id, message)
                VALUES (%s, %s)
                RETURNING feedback_id, created_at
            """
            self.cursor.execute(fallback_query, (user_id, f"Cancellation reason: {reason}"))
            result = self.cursor.fetchone()
            return {
                "feedback_id": str(result[0]),
                "created_at": result[1].isoformat()
            }

    def complete_onboarding(self, user_id, gender):
        """Mark user as having completed onboarding and set their gender."""
        query = """
            UPDATE users
            SET user_status = 'onboarded', gender = %s
            WHERE user_id = %s
            RETURNING user_id
        """
        try:
            self.cursor.execute(query, (gender, user_id))
            result = self.cursor.fetchone()

            if not result:
                raise Exception(f"User {user_id} not found")

            return {"success": True}

        except DatabaseError as e:
            self.conn.rollback()
            raise e
        except Exception as e:
            self.conn.rollback()
            raise e

    def get_default_previews(self, gender: str, ids: list = None):
        """
        Get preview images from defaults table by gender and optional IDs.
        Used for onboarding clothing selection.
        """
        try:
            if ids:
                query = """
                    SELECT id, preview_bytes
                    FROM defaults
                    WHERE gender = %s AND id = ANY(%s)
                    ORDER BY id
                """
                self.cursor.execute(query, (gender, ids))
            else:
                query = """
                    SELECT id, preview_bytes
                    FROM defaults
                    WHERE gender = %s
                    ORDER BY id
                """
                self.cursor.execute(query, (gender,))

            results = self.cursor.fetchall()
            return [
                {"id": row[0], "base64": base64.b64encode(row[1]).decode('utf-8')}
                for row in results
            ]

        except DatabaseError as e:
            self.conn.rollback()
            raise e

    def get_default_image(self, default_id: int):
        """
        Get full image bytes and UUID from defaults table by ID.
        Used for onboarding design generation.
        Returns dict with image_id (UUID) and image_bytes.
        """
        query = """
            SELECT image_id, image_bytes
            FROM defaults
            WHERE id = %s
        """
        try:
            self.cursor.execute(query, (default_id,))
            result = self.cursor.fetchone()

            if not result:
                return None

            return {
                "image_id": str(result[0]),
                "image_bytes": result[1]
            }

        except DatabaseError as e:
            self.conn.rollback()
            raise e

    def copy_defaults_to_user(self, user_id, gender: str):
        """
        Copy all default images for given gender to user's images table.
        Uses same image_id (UUID) from defaults table.
        Category = 'clothing'.
        Decrements storage_left for each image copied.
        Returns list of copied image previews for frontend update.
        """
        # Get all defaults for gender
        get_defaults_query = """
            SELECT image_id, image_bytes, preview_bytes
            FROM defaults
            WHERE gender = %s
        """

        # Insert into images table (uses same UUID)
        insert_query = """
            INSERT INTO images (image_id, user_id, category, image_bytes, preview_bytes)
            VALUES (%s, %s, 'clothing', %s, %s)
            RETURNING created_at
        """

        # Decrement storage for all copied images at once
        decrement_query = """
            UPDATE users SET storage_left = storage_left - %s
            WHERE user_id = %s
            RETURNING storage_left
        """

        try:
            self.cursor.execute(get_defaults_query, (gender,))
            defaults = self.cursor.fetchall()

            if not defaults:
                return {"copied_images": [], "storage_left": None}

            copied_images = []
            for row in defaults:
                image_id, image_bytes, preview_bytes = row

                self.cursor.execute(insert_query, (
                    image_id,
                    user_id,
                    image_bytes,
                    preview_bytes
                ))
                result = self.cursor.fetchone()
                created_at = result[0]

                copied_images.append({
                    "id": str(image_id),
                    "base64": base64.b64encode(preview_bytes).decode('utf-8'),
                    "faved": False,
                    "created_at": created_at.isoformat()
                })

            # Decrement storage_left by number of copied images
            self.cursor.execute(decrement_query, (len(defaults), user_id))
            storage_result = self.cursor.fetchone()
            new_storage_left = storage_result[0] if storage_result else None

            return {
                "copied_images": copied_images,
                "storage_left": new_storage_left
            }

        except DatabaseError as e:
            self.conn.rollback()
            raise e

    def insert_default_image(self, gender: str, image_bytes: bytes, preview_bytes: bytes):
        """
        Insert a default image into the defaults table.
        Used by utility script to populate onboarding images.
        """
        query = """
            INSERT INTO defaults (gender, image_bytes, preview_bytes)
            VALUES (%s, %s, %s)
            RETURNING id
        """
        try:
            self.cursor.execute(query, (gender, image_bytes, preview_bytes))
            result = self.cursor.fetchone()
            return result[0]

        except DatabaseError as e:
            self.conn.rollback()
            raise e
