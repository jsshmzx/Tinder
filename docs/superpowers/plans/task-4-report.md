# Task 4 Report: Append 4 new test functions

## Summary

Added 4 new unit tests to `tests/unit/test_api_v1_admin_questions.py` for admin question endpoints:

1. **`test_create_question_choice_rejects_duplicate_options`** — choice with `["A", "A", "B"]` returns 422
2. **`test_update_question_true_false_validates_answer`** — updating answer to `"maybe"` on a true_false question returns 400 with `"判断题"`
3. **`test_update_question_at_least_one_field`** — empty `{}` update body returns 422
4. **`test_update_question_choice_answer_not_in_options`** — updating answer to `"C"` with options `["A", "B"]` returns 400 with `"答案必须在选项中"`

All 4 new tests pass.

## Pre-existing failures (not caused by this change)

3 tests in the file were already failing before this change:
- `test_create_question_choice` — `fake_create()` takes 1 positional arg but 2 were given
- `test_create_question_true_false_valid` — same issue
- `test_create_question_fill_blank` — same issue

These are pre-existing bugs where `fake_create` is defined with `(data)` but `RegisterQuestionsDAO.create` is an instance method and passes `self` as the first argument. Fix would be: change signature to `async def fake_create(self, data)`.

## Files changed

- `tests/unit/test_api_v1_admin_questions.py` — appended 4 new test functions
