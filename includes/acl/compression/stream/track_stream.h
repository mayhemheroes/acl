#pragma once

////////////////////////////////////////////////////////////////////////////////
// The MIT License (MIT)
//
// Copyright (c) 2017 Nicholas Frechette & Animation Compression Library contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
////////////////////////////////////////////////////////////////////////////////

#include "acl/core/memory.h"
#include "acl/core/error.h"
#include "acl/core/algorithm_types.h"
#include "acl/math/quat_64.h"
#include "acl/math/quat_packing.h"
#include "acl/math/vector4_64.h"
#include "acl/math/vector4_packing.h"

#include <stdint.h>

namespace acl
{
	class TrackStream
	{
	public:
		uint8_t* get_raw_sample_ptr(uint32_t sample_index)
		{
			ACL_ENSURE(sample_index < m_num_samples, "Invalid sample index. %u >= %u", sample_index, m_num_samples);
			uint32_t offset = sample_index * m_sample_size;
			return m_samples + offset;
		}

		const uint8_t* get_raw_sample_ptr(uint32_t sample_index) const
		{
			ACL_ENSURE(sample_index < m_num_samples, "Invalid sample index. %u >= %u", sample_index, m_num_samples);
			uint32_t offset = sample_index * m_sample_size;
			return m_samples + offset;
		}

		template<typename SampleType>
		SampleType get_raw_sample(uint32_t sample_index) const
		{
			const uint8_t* ptr = get_raw_sample_ptr(sample_index);
			return *safe_ptr_cast<const SampleType>(ptr);
		}

		template<typename SampleType>
		void set_raw_sample(uint32_t sample_index, const SampleType& sample)
		{
			ACL_ENSURE(m_sample_size == sizeof(SampleType), "Unexpected sample size. %u != %u", m_sample_size, sizeof(SampleType));
			uint8_t* ptr = get_raw_sample_ptr(sample_index);
			*safe_ptr_cast<SampleType>(ptr) = sample;
		}

		uint32_t get_num_samples() const { return m_num_samples; }
		uint32_t get_sample_size() const { return m_sample_size; }
		uint32_t get_sample_rate() const { return m_sample_rate; }
		AnimationTrackType8 get_track_type() const { return m_type; }
		double get_duration() const
		{
			ACL_ENSURE(m_sample_rate > 0, "Invalid sample rate: %u", m_sample_rate);
			return (m_num_samples - 1) * (1.0 / m_sample_rate);
		}

	protected:
		TrackStream(AnimationTrackType8 type, TrackFormat8 format) : m_allocator(nullptr), m_samples(nullptr), m_num_samples(0), m_sample_size(0), m_type(type), m_format(format) {}
		TrackStream(Allocator& allocator, uint32_t num_samples, uint32_t sample_size, uint32_t sample_rate, AnimationTrackType8 type, TrackFormat8 format)
			: m_allocator(&allocator)
			, m_samples(reinterpret_cast<uint8_t*>(allocator.allocate(sample_size * num_samples, 16)))
			, m_num_samples(num_samples)
			, m_sample_size(sample_size)
			, m_sample_rate(sample_rate)
			, m_type(type)
			, m_format(format)
		{}
		TrackStream(const TrackStream&) = delete;
		TrackStream(TrackStream&& other)
			: m_allocator(other.m_allocator)
			, m_samples(other.m_samples)
			, m_num_samples(other.m_num_samples)
			, m_sample_size(other.m_sample_size)
			, m_sample_rate(other.m_sample_rate)
			, m_type(other.m_type)
			, m_format(other.m_format)
		{
			new(&other) TrackStream(other.m_type, other.m_format);
		}

		~TrackStream()
		{
			if (m_allocator != nullptr && m_num_samples != 0)
				m_allocator->deallocate(m_samples, m_sample_size * m_num_samples);
		}

		TrackStream& operator=(const TrackStream&) = delete;
		TrackStream& operator=(TrackStream&& rhs)
		{
			std::swap(m_allocator, rhs.m_allocator);
			std::swap(m_samples, rhs.m_samples);
			std::swap(m_num_samples, rhs.m_num_samples);
			std::swap(m_sample_size, rhs.m_sample_size);
			std::swap(m_sample_rate, rhs.m_sample_rate);
			std::swap(m_type, rhs.m_type);
			std::swap(m_format, rhs.m_format);
			return *this;
		}

		void duplicate(TrackStream& copy) const
		{
			ACL_ENSURE(copy.m_type == m_type, "Attempting to duplicate streams with incompatible types!");
			if (m_allocator != nullptr)
			{
				copy.m_allocator = m_allocator;
				copy.m_samples = reinterpret_cast<uint8_t*>(m_allocator->allocate(m_sample_size * m_num_samples, 16));
				copy.m_num_samples = m_num_samples;
				copy.m_sample_size = m_sample_size;
				copy.m_sample_rate = m_sample_rate;
				copy.m_format = m_format;

				std::memcpy(copy.m_samples, m_samples, m_sample_size * m_num_samples);
			}
		}

		Allocator*				m_allocator;
		uint8_t*				m_samples;
		uint32_t				m_num_samples;
		uint32_t				m_sample_size;
		uint32_t				m_sample_rate;

		AnimationTrackType8		m_type;
		TrackFormat8			m_format;
	};

	class RotationTrackStream : public TrackStream
	{
	public:
		RotationTrackStream() : TrackStream(AnimationTrackType8::Rotation, TrackFormat8(RotationFormat8::Quat_128)) {}
		RotationTrackStream(Allocator& allocator, uint32_t num_samples, uint32_t sample_size, uint32_t sample_rate, RotationFormat8 format)
			: TrackStream(allocator, num_samples, sample_size, sample_rate, AnimationTrackType8::Rotation, TrackFormat8(format))
		{}
		RotationTrackStream(const RotationTrackStream&) = delete;
		RotationTrackStream(RotationTrackStream&& other)
			: TrackStream(std::forward<TrackStream>(other))
		{}

		RotationTrackStream& operator=(const RotationTrackStream&) = delete;
		RotationTrackStream& operator=(RotationTrackStream&& rhs)
		{
			TrackStream::operator=(std::forward<TrackStream>(rhs));
			return *this;
		}

		RotationTrackStream duplicate() const
		{
			RotationTrackStream copy;
			TrackStream::duplicate(copy);
			return copy;
		}

		RotationFormat8 get_rotation_format() const { return m_format.rotation; }
	};

	class TranslationTrackStream : public TrackStream
	{
	public:
		TranslationTrackStream() : TrackStream(AnimationTrackType8::Translation, TrackFormat8(VectorFormat8::Vector3_96)) {}
		TranslationTrackStream(Allocator& allocator, uint32_t num_samples, uint32_t sample_size, uint32_t sample_rate, VectorFormat8 format)
			: TrackStream(allocator, num_samples, sample_size, sample_rate, AnimationTrackType8::Translation, TrackFormat8(format))
		{}
		TranslationTrackStream(const TranslationTrackStream&) = delete;
		TranslationTrackStream(TranslationTrackStream&& other)
			: TrackStream(std::forward<TrackStream>(other))
		{}

		TranslationTrackStream& operator=(const TranslationTrackStream&) = delete;
		TranslationTrackStream& operator=(TranslationTrackStream&& rhs)
		{
			TrackStream::operator=(std::forward<TrackStream>(rhs));
			return *this;
		}

		TranslationTrackStream duplicate() const
		{
			TranslationTrackStream copy;
			TrackStream::duplicate(copy);
			return copy;
		}

		VectorFormat8 get_vector_format() const { return m_format.vector; }
	};

	// For a rotation track, the extent only tells us if the track is constant or not
	// since the min/max we maintain aren't valid rotations.
	// Similarly, the center isn't a valid rotation and is meaningless.
	class TrackStreamRange
	{
	public:
		TrackStreamRange()
			: m_min(vector_set(0.0))
			, m_max(vector_set(0.0))
		{}

		TrackStreamRange(const Vector4_64& min, const Vector4_64& max)
			: m_min(min)
			, m_max(max)
		{}

		Vector4_64 get_min() const { return m_min; }
		Vector4_64 get_max() const { return m_max; }

		Vector4_64 get_center() const { return vector_mul(vector_add(m_max, m_min), 0.5); }
		Vector4_64 get_extent() const { return vector_sub(m_max, m_min); }

		bool is_constant(double threshold) const { return vector_all_less_than(vector_abs(vector_sub(m_max, m_min)), vector_set(threshold)); }

	private:
		Vector4_64	m_min;
		Vector4_64	m_max;
	};

	struct BoneStreams
	{
		RotationTrackStream rotations;
		TranslationTrackStream translations;

		TrackStreamRange rotation_range;
		TrackStreamRange translation_range;

		bool is_rotation_constant;
		bool is_rotation_default;
		bool is_translation_constant;
		bool is_translation_default;
		bool are_rotations_normalized;
		bool are_translations_normalized;

		bool is_rotation_animated() const { return !is_rotation_constant && !is_rotation_default; }
		bool is_translation_animated() const { return !is_translation_constant && !is_translation_default; }

		BoneStreams duplicate() const
		{
			BoneStreams copy;
			copy.rotations = rotations.duplicate();
			copy.translations = translations.duplicate();
			copy.rotation_range = rotation_range;
			copy.translation_range = translation_range;
			copy.is_rotation_constant = is_rotation_constant;
			copy.is_rotation_default = is_rotation_default;
			copy.is_translation_constant = is_translation_constant;
			copy.is_translation_default = is_translation_default;
			copy.are_rotations_normalized = are_rotations_normalized;
			copy.are_translations_normalized = are_translations_normalized;
			return copy;
		}

		Quat_64 get_rotation_sample(uint32_t sample_index) const
		{
			const uint8_t* quantized_ptr = rotations.get_raw_sample_ptr(sample_index);
			bool is_raw_precision = rotations.get_sample_size() == sizeof(Quat_64);

			Vector4_32 packed_rotation;
			Vector4_64 packed_raw_rotation;

			RotationFormat8 format = rotations.get_rotation_format();
			switch (format)
			{
			case RotationFormat8::Quat_128:
				if (is_raw_precision)
					packed_raw_rotation = vector_unaligned_load(safe_ptr_cast<const double>(quantized_ptr));
				else
					packed_rotation = vector_to_quat(unpack_vector4_128(quantized_ptr));
				break;
			case RotationFormat8::QuatDropW_96:
				if (is_raw_precision)
					packed_raw_rotation = vector_unaligned_load(safe_ptr_cast<const double>(quantized_ptr));
				else
					packed_rotation = vector_to_quat(unpack_vector3_96(quantized_ptr));
				break;
			case RotationFormat8::QuatDropW_48:
				if (is_raw_precision)
					packed_raw_rotation = vector_unaligned_load(safe_ptr_cast<const double>(quantized_ptr));
				else
					packed_rotation = vector_to_quat(unpack_vector3_48(quantized_ptr));
				break;
			case RotationFormat8::QuatDropW_32:
				if (is_raw_precision)
					packed_raw_rotation = vector_unaligned_load(safe_ptr_cast<const double>(quantized_ptr));
				else
					packed_rotation = vector_to_quat(unpack_vector3_32<11, 11, 10>(quantized_ptr));
				break;
			case RotationFormat8::QuatDropW_Variable:
			default:
				ACL_ENSURE(false, "Invalid or unsupported rotation format: %s", get_rotation_format_name(format));
				packed_rotation = vector_zero_32();
				break;
			}

			if (are_rotations_normalized)
			{
				Vector4_64 clip_range_min = rotation_range.get_min();
				Vector4_64 clip_range_extent = rotation_range.get_extent();

				if (is_raw_precision)
					packed_raw_rotation = vector_mul_add(packed_raw_rotation, clip_range_extent, clip_range_min);
				else
					packed_rotation = vector_mul_add(packed_rotation, vector_cast(clip_range_extent), vector_cast(clip_range_min));
			}

			switch (format)
			{
			case RotationFormat8::Quat_128:
				return is_raw_precision ? vector_to_quat(packed_raw_rotation) : quat_cast(vector_to_quat(packed_rotation));
			case RotationFormat8::QuatDropW_96:
			case RotationFormat8::QuatDropW_48:
			case RotationFormat8::QuatDropW_32:
				return is_raw_precision ? quat_from_positive_w(packed_raw_rotation) : quat_cast(quat_from_positive_w(packed_rotation));
			case RotationFormat8::QuatDropW_Variable:
			default:
				ACL_ENSURE(false, "Invalid or unsupported rotation format: %s", get_rotation_format_name(format));
				return quat_identity_64();
			}
		}

		Vector4_64 get_translation_sample(uint32_t sample_index) const
		{
			const uint8_t* quantized_ptr = translations.get_raw_sample_ptr(sample_index);
			bool is_raw_precision = translations.get_sample_size() == sizeof(Vector4_64);

			Vector4_32 packed_translation;
			Vector4_64 packed_raw_translation;

			VectorFormat8 format = translations.get_vector_format();
			switch (format)
			{
			case VectorFormat8::Vector3_96:
				if (is_raw_precision)
					packed_raw_translation = vector_unaligned_load(safe_ptr_cast<const double>(quantized_ptr));
				else
					packed_translation = unpack_vector3_96(quantized_ptr);
				break;
			case VectorFormat8::Vector3_48:
				packed_translation = unpack_vector3_48(quantized_ptr);
				break;
			case VectorFormat8::Vector3_32:
				packed_translation = unpack_vector3_32<11, 11, 10>(quantized_ptr);
				break;
			case VectorFormat8::Vector3_Variable:
			default:
				ACL_ENSURE(false, "Invalid or unsupported vector format: %s", get_vector_format_name(format));
				packed_translation = vector_zero_32();
				break;
			}

			if (are_translations_normalized)
			{
				Vector4_64 clip_range_min = translation_range.get_min();
				Vector4_64 clip_range_extent = translation_range.get_extent();

				if (is_raw_precision)
					packed_raw_translation = vector_mul_add(packed_raw_translation, clip_range_extent, clip_range_min);
				else
					packed_translation = vector_mul_add(packed_translation, vector_cast(clip_range_extent), vector_cast(clip_range_min));
			}

			return is_raw_precision ? packed_raw_translation : vector_cast(packed_translation);
		}
	};

	inline uint32_t get_animated_num_samples(const BoneStreams* bone_streams, uint16_t num_bones)
	{
		uint32_t num_samples = 1;
		for (uint16_t bone_index = 0; bone_index < num_bones; ++bone_index)
		{
			const BoneStreams& bone_stream = bone_streams[bone_index];
			num_samples = std::max(num_samples, bone_stream.rotations.get_num_samples());
			num_samples = std::max(num_samples, bone_stream.translations.get_num_samples());

			if (num_samples != 1)
				break;
		}

		return num_samples;
	}
}
